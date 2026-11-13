# Contributing to Event Horizon

Thanks for helping. Event Horizon is part of the [LLCForge](https://github.com/LLCForge) network tooling suite and is built by and for network and IT engineers. Every kind of contribution is welcome: bug reports, documentation, test fixtures, features and reviews.

## Ground rules

- Be respectful. All participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
- Security issues go through [SECURITY.md](SECURITY.md), never public issues.
- Discuss large changes in an issue before writing the code, so effort is not wasted.

## Development setup

```bash
git clone https://github.com/LLCForge/Event-Horizon.git
cd Event-Horizon
cargo build
cargo test
```

Requirements: recent stable Rust via [rustup](https://rustup.rs), plus `rustfmt` and `clippy` components.

## Before you open a pull request

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

All three must pass; CI runs the same commands.

## Code guidelines

- No `unsafe` in protocol or input parsing code. If you believe `unsafe` is required elsewhere, explain why in the PR.
- No `unwrap()` / `expect()` on data that comes from the network, a feed, a file or a user.
- Every parser change comes with tests, including malformed and oversized input.
- New dependencies must be justified in the PR description; prefer well-maintained crates with a small dependency tree.
- Keep [ARCHITECTURE.md](ARCHITECTURE.md) in sync with design changes.
- User-facing changes update **both** [README.md](README.md) and [README.tr.md](README.tr.md). If you cannot write one of the languages, say so in the PR and a maintainer will help.

## Test data

- Use documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and private-use ASNs (`64496-64511`, `65536-65551`) in examples and fixtures.
- Never commit real customer prefixes, packet captures with personal data, credentials or tokens.

## Commit and PR style

- Small, focused commits with clear messages ([Conventional Commits](https://www.conventionalcommits.org) style is preferred: `fix(parser): ...`, `feat(alerts): ...`).
- One logical change per pull request; link the related issue.
- Mark breaking changes clearly in the PR title and description.

## License of contributions

By submitting a contribution you agree that it is licensed under the project's [MIT License](LICENSE), the same license as the rest of the code.
