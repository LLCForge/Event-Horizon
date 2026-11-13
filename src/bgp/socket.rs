//! Outgoing BGP TCP socket: local source address, multihop TTL and RFC 2385
//! TCP-MD5 signatures.
//!
//! TCP-MD5 needs kernel support exposed through `setsockopt(TCP_MD5SIG)`,
//! which only Linux offers to unprivileged programs. On macOS and Windows a
//! session that requires it is refused with a clear error.

use std::io;
use std::net::{IpAddr, SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream};

/// RFC 2385 allows up to 80 bytes of key material (Linux `TCP_MD5SIG_MAXKEYLEN`).
pub const MD5_MAX_KEY: usize = 80;

#[derive(Clone, Default)]
pub struct SocketOptions {
    pub local: Option<IpAddr>,
    pub ttl: Option<u8>,
    pub md5_key: Option<Vec<u8>>,
}

impl std::fmt::Debug for SocketOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketOptions")
            .field("local", &self.local)
            .field("ttl", &self.ttl)
            .field("md5", &self.md5_key.is_some())
            .finish()
    }
}

/// True when this build can sign BGP sessions with TCP-MD5.
pub const fn md5_supported() -> bool {
    cfg!(target_os = "linux")
}

pub fn md5_unsupported_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-MD5 (RFC 2385) session authentication is only available on Linux; \
         macOS and Windows do not expose TCP_MD5SIG to applications. Refusing to \
         open a session that requires it.",
    )
}

/// Opens the socket with all options applied before the SYN is sent.
pub async fn connect(addr: SocketAddr, opts: &SocketOptions) -> io::Result<TcpStream> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if let Some(l) = opts.local {
        sock.bind(&SocketAddr::new(l, 0).into())?;
    }
    if let Some(ttl) = opts.ttl {
        if addr.is_ipv4() {
            sock.set_ttl_v4(u32::from(ttl))?;
        } else {
            sock.set_unicast_hops_v6(u32::from(ttl))?;
        }
    }
    if let Some(key) = &opts.md5_key {
        set_md5(&sock, addr, key)?;
    }
    sock.set_nonblocking(true)?;
    let std: std::net::TcpStream = sock.into();
    TcpSocket::from_std_stream(std).connect(addr).await
}

#[cfg(not(target_os = "linux"))]
fn set_md5(_sock: &Socket, _peer: SocketAddr, _key: &[u8]) -> io::Result<()> {
    Err(md5_unsupported_error())
}

/// `struct sockaddr_storage` sized and aligned buffer.
#[cfg(target_os = "linux")]
#[repr(C, align(8))]
struct Storage([u8; 128]);

/// Linux `struct tcp_md5sig` (include/uapi/linux/tcp.h).
#[cfg(target_os = "linux")]
#[repr(C)]
struct TcpMd5Sig {
    addr: Storage,
    flags: u8,
    prefixlen: u8,
    keylen: u16,
    ifindex: i32,
    key: [u8; MD5_MAX_KEY],
}

/// Builds the peer `sockaddr_in` / `sockaddr_in6` bytes without unsafe code.
#[cfg(target_os = "linux")]
fn sockaddr_bytes(peer: SocketAddr) -> Storage {
    let mut s = [0u8; 128];
    match peer.ip() {
        IpAddr::V4(a) => {
            s[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            s[4..8].copy_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            s[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            s[8..24].copy_from_slice(&a.octets());
        }
    }
    Storage(s)
}

#[cfg(target_os = "linux")]
fn set_md5(sock: &Socket, peer: SocketAddr, key: &[u8]) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if key.is_empty() || key.len() > MD5_MAX_KEY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TCP-MD5 password must be 1-{MD5_MAX_KEY} bytes"),
        ));
    }
    let mut sig = TcpMd5Sig {
        addr: sockaddr_bytes(peer),
        flags: 0,
        prefixlen: 0,
        keylen: key.len() as u16,
        ifindex: 0,
        key: [0; MD5_MAX_KEY],
    };
    sig.key[..key.len()].copy_from_slice(key);
    // SAFETY: `sig` is a fully initialised #[repr(C)] mirror of the kernel's
    // `struct tcp_md5sig`; the pointer and length describe exactly that value,
    // which outlives the call, and the fd is owned by `sock`. This is the only
    // unsafe block in Event Horizon.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            std::ptr::addr_of!(sig).cast::<libc::c_void>(),
            std::mem::size_of::<TcpMd5Sig>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn binds_local_address_and_sets_ttl() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let opts = SocketOptions {
            local: Some("127.0.0.1".parse().unwrap()),
            ttl: Some(2),
            md5_key: None,
        };
        let (s, accepted) = tokio::join!(connect(addr, &opts), l.accept());
        let s = s.unwrap();
        assert_eq!(s.local_addr().unwrap().ip(), opts.local.unwrap());
        assert_eq!(s.ttl().unwrap(), 2);
        assert_eq!(accepted.unwrap().1, s.local_addr().unwrap());
        assert!(!format!("{opts:?}").contains("md5_key"));
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn md5_is_refused_with_a_clear_error() {
        assert!(!md5_supported());
        let opts = SocketOptions {
            md5_key: Some(b"secret".to_vec()),
            ..Default::default()
        };
        let e = connect("127.0.0.1:9".parse().unwrap(), &opts)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert!(e.to_string().contains("only available on Linux"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn md5_sockopt_is_accepted_by_linux() {
        assert!(md5_supported());
        assert_eq!(std::mem::size_of::<TcpMd5Sig>(), 216);
        let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        set_md5(&s, "127.0.0.1:179".parse().unwrap(), b"secret").unwrap();
        let s6 = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).unwrap();
        set_md5(&s6, "[::1]:179".parse().unwrap(), b"secret").unwrap();
        assert!(set_md5(&s, "127.0.0.1:179".parse().unwrap(), &[b'x'; 81]).is_err());
    }
}
