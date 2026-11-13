# Homebrew formula for Event Horizon.
# Rendered by sync.py; @VERSION@ and the @SHA256_*@ values are filled in by the
# release workflow (job "publish", step "Render package-manager manifests") and
# shipped in event-horizon-<version>-package-manifests.tar.gz. Copy the rendered file
# into the tap repository (LLCForge/homebrew-tap, Formula/event-horizon.rb).
class EventHorizon < Formula
  desc "Automated guard-railed RTBH and FlowSpec DDoS mitigation over BGP"
  homepage "https://github.com/LLCForge/Event-Horizon"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/LLCForge/Event-Horizon/releases/download/v@VERSION@/event-horizon-@VERSION@-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256_AARCH64_APPLE_DARWIN@"
    end
    on_intel do
      url "https://github.com/LLCForge/Event-Horizon/releases/download/v@VERSION@/event-horizon-@VERSION@-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256_X86_64_APPLE_DARWIN@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/LLCForge/Event-Horizon/releases/download/v@VERSION@/event-horizon-@VERSION@-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_AARCH64_LINUX_MUSL@"
    end
    on_intel do
      url "https://github.com/LLCForge/Event-Horizon/releases/download/v@VERSION@/event-horizon-@VERSION@-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_X86_64_LINUX_MUSL@"
    end
  end

  def install
    bin.install "event-horizon"
    pkgetc.install "event-horizon.example.toml" if File.exist?("event-horizon.example.toml")
    doc.install Dir["README*.md"]
  end

  service do
    run [opt_bin/"event-horizon", "run", "--config", etc/"event-horizon/event-horizon.toml"]
    environment_variables STATE_DIRECTORY: var/"lib/event-horizon"
    keep_alive successful_exit: false
    log_path var/"log/event-horizon.log"
    error_log_path var/"log/event-horizon.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/event-horizon --version")
  end
end
