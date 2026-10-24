# gdhcn-helper - Rust port

Port of the Python service in `../../`. Design rationale, the Kotlin-vs-Rust
comparison and the step sequencing are in [../../docs/PORT-PLAN.md](../../docs/PORT-PLAN.md).

## Status

| Plan step | Module | State |
|---|---|---|
| 0 - golden fixtures | `../../fixtures/` | **done** - 3 real QR payloads decoded by the reference service |
| 2 - base45 | `src/base45.rs` | **done** - 7 unit tests (spec vectors, round-trip, 4 error paths) + cross-check against the reference fixtures; clippy `-D warnings` clean |
| 2 - zlib / CBOR / COSE | - | not started |
| 3 - trust list + verification | - | not started |
| 4 - SHLink legs | - | not started |
| 5 - HTTP + OpenAPI | - | not started |

Builds and tests green in a container (see *Building*). The base45 suite
asserts the four vectors from draft-faltstrom-base45, round-trip over every
length 0..64, four error paths, and -- via `tests/fixtures.rs` -- that decoding
the three real WHO QR payloads yields byte counts identical to the reference
Python service's own `diagnostics.base45_decoded_len`, with the zlib header
where it should be.

## Building

The Windows host cannot run `rustc`: **Smart App Control is in enforcement
mode**, which blocks unsigned downloaded executables. A toolchain is installed
at `%USERPROFILE%\.cargo` but every binary is blocked (CodeIntegrity events
3077/3033). That setting is one-way -- disabling it requires reinstalling
Windows -- so do not try to work around it on the host.

Two routes that work:

```sh
# 1. Container (preferred: also how the service ships)
docker build -f Dockerfile.test -t gdhcn-rust-test .

# 2. WSL (Ubuntu-26.04 is present); needs a linker, hence one sudo step
wsl -d Ubuntu-26.04
sudo apt-get update && sudo apt-get install -y build-essential pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
cd /mnt/e/work/WHO/WHO-ITB/gdhcn-helper/ports/rust && cargo test
```

`Dockerfile.test` runs clippy with `-D warnings`, the test suite, and a release
build, so a successful image build is a green suite.

## Conventions

- **Pure-Rust dependencies only** -- no C build scripts, so the image needs
  only a linker and the binary stays static.
- Dependencies are added as modules land, so a build failure is always about
  code that exists.
- `Cargo.lock` is committed: this is an application, not a library.
