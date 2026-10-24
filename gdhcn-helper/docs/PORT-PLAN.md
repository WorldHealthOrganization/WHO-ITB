# Porting gdhcn-helper off Python

Status: **plan only, not started.** Written for whoever picks up the port.

## Decision

The choice is **Kotlin or Rust**. (Java was considered and dropped: same JVM,
same libraries, more ceremony.)

**Recommendation: Kotlin.** Choose Rust only if container footprint or cold
start is a hard deployment constraint — see *Standalone and footprint* below,
which is the one place Rust keeps an advantage that Kotlin cannot close.

Two reasons, in order of weight.

### 1. JSON-LD URDNA2015 canonicalization is the crux

Everything else in this service is well-trodden format conversion with solid
libraries on both sides. Canonicalization is different: it must produce
**byte-identical** N-Quads or the `JsonWebSignature2020` check on the GDHCN
trust list fails. And it is not generic canonicalization — it runs against
four specific contexts including WHO's own `tng-additional-context/v1`
([app.py:52](../app.py#L52)), with remote-override fallbacks because that
context is not reliably resolvable as JSON-LD.

On the JVM, `titanium-json-ld` is the reference-grade implementation and
JSON-LD 1.1 + URDNA2015 is its core competence. In Rust the path is
spruceid's `ssi` / `json-ld` plus `rdf-canon` — real and actively developed,
but a far smaller user base for this exact combination. **Treat the Rust
option's canonicalization as unverified until the spike in step 1 proves it.**

### 2. Everything around this service is already JVM

`gitb-ui` is Scala/Play, `gitb-srv` is Java, the FHIR validator is
`validator_cli.jar`. HAPI FHIR — directly relevant to the `/shlink/fetch-fhir`
leg — is JVM. A JVM service shares base images, build tooling and the team's
existing fluency with its neighbours. Separately, the EU DCC reference
implementations for HCERT/COSE/base45 are predominantly Java/Kotlin, so parts
of the decode path become reuse rather than reimplementation.

### Where Rust genuinely wins

Footprint and startup — the numbers are in *Standalone and footprint* below.
If this ever runs as a per-test-session sidecar, or as many instances at the
edge, that ratio is the whole argument. Also no GC pauses, and a stronger
story for parsing untrusted QR/CBOR input — though Kotlin is memory-safe here
too, so that last edge is smaller than it first appears.

## Capability inventory

2062 lines of Python, 12 endpoints. The weight is uneven: `/verify/signature`
alone is ~305 lines ([app.py:1087](../app.py#L1087)) and `/decode/hcert` ~138.

| Concern | Python today | Rust | Kotlin |
|---|---|---|---|
| HTTP + CORS | Flask, flask-cors | axum + tower-http | Ktor (prefer over Spring Boot at this size) |
| OpenAPI | hand-written dict | utoipa (from types) | springdoc / Ktor plugin |
| Base45 | `base45` | `base45` | trivial; EU DCC impl exists |
| zlib | stdlib | `flate2` | `java.util.zip` (stdlib) |
| CBOR | `cbor2` | `ciborium` | upokecenter CBOR, Jackson-CBOR |
| COSE_Sign1 | hand-rolled | `coset` (Google) | `cose-java` (EU DCC) |
| ES256 / P-256 JWK | `cryptography` | `p256` (RustCrypto) | JCA + Nimbus JOSE |
| JWS detached payload | `jwcrypto` | `josekit` | Nimbus JOSE+JWT |
| **JSON-LD URDNA2015** | **PyLD** | `json-ld` + `rdf-canon` | **titanium-json-ld** |
| DID:web resolution | `requests` | `reqwest` | Ktor client / java.net.http |
| QR decode | `pyzbar` (native zbar) | `rqrr` (pure Rust) | ZXing |

## Standalone and footprint

Both options are standalone and REST-enabled. A Kotlin/Ktor build is a fat JAR
run as `java -jar hcert-decoder.jar` — no servlet container, the same
operational shape as `python app.py` today and as the `fhir-validator` service
already in the compose stack. Rust is a single static binary.

The difference is what you ship. The current Python image is **888 MB**:

| | Image | Cold start |
|---|---|---|
| Python today | ~888 MB | ~1 s |
| Kotlin fat JAR on `temurin-jre-alpine` | ~150-200 MB | ~0.3-0.8 s |
| Kotlin + `jlink` trimmed runtime | ~80-120 MB | ~0.3-0.8 s |
| Rust static binary | ~15 MB | ~5 ms |

**GraalVM native-image does not rescue the Kotlin option here.**
`titanium-json-ld`, Nimbus and BouncyCastle lean on reflection and service
loaders, which is what native-image handles worst — so you would be fighting
the exact library that makes Kotlin the recommendation. Possible with
configuration, but do not plan the footprint around it. If a single static
binary is a requirement, that is the argument for Rust, and it should be
weighed against the canonicalization risk in step 1.

Either way the port is a good moment to **drop the `hcert-gherkin-dialect`
nginx sidecar**: it exists only because `validator_cli.jar` cannot serve static
files and the Python app never took the job. Either target can serve
`/gherkin-dialect/*` itself.

## Plan

Step 0 is language-independent and is the real de-risking move, so it can
start before the decision is final.

| # | Step | Notes |
|---|---|---|
| 0 | **Golden-fixture harness** | Capture real trust-list DID documents with the exact N-Quads today's PyLD produces, plus real HC1 strings with their decoded COSE/CWT. Freeze as fixtures; any port must match byte-for-byte. **Must capture the current service's lenient behaviour, not just spec-conformant paths** — see the warning below. Also protects the Python service against its own dependency drift, so it pays for itself even if the port never happens. |
| 1 | **Canonicalization spike** | Feed the fixtures through and diff N-Quads. A day or two, and it answers the only genuinely open question. Do it in both languages if a true comparison is wanted. |
| 2 | **Decode pipeline** | QR → base45 → zlib → CBOR → COSE_Sign1 → CWT. Pure functions, fully covered by fixtures. `/decode/image`, `/decode/hcert`, `/extract/metadata`, `/extract/reference`. |
| 3 | **Trust list + verification** | DID:web resolution, context loading with the local-first/remote-override policy, JWS2020 verify, key extraction, ES256 check. The four `/gdhcn/*` routes and `/verify/signature` — the hard half. |
| 4 | **SHLink legs** | `/shlink/authorize`, `/shlink/fetch-fhir`. Mostly HTTP plumbing; consider HAPI for FHIR parsing on the JVM. |
| 5 | **OpenAPI parity** | Generate the spec from types instead of hand-maintaining a dict — then the README/route drift that produced the `/swagger` 404 becomes structurally impossible. |
| 6 | **Cut over** | Run both behind the compose stack, replay fixtures and the ITB hcert suites against each, then swap the image. |

### Do not "fix" the leniency

A clean-room rewrite will naturally implement the SMART Health Links spec. This
service is deliberately lenient in ways the test setup now depends on:

- `/shlink/authorize` falls back to `GET ?passcode=`
  ([app.py:806](../app.py#L806)). Not sanctioned by the spec, and the only
  reason the GitHub Pages fixture in [`tools/`](../tools/README.md) resolves at
  all.
- It reads **cleartext** FHIR where the spec expects JWE; there is no
  decryption anywhere in the codebase.
- It never branches on the SHLink `flag`, so the `U` (direct-file) path is
  unimplemented.

Port these away without replacing the fixtures and the SHL test setup silently
stops working. Decide deliberately per item: preserve, or change it and update
the fixtures in the same commit.

## Progress tracker

| Milestone | State | Date |
|---|---|---|
| Language decided | Rust first; Kotlin to follow (both wanted) | 2026-10-24 |
| Step 0 — fixtures | **done** — 3 real QR payloads + reference decode in [`../fixtures/`](../fixtures/) | 2026-10-24 |
| Step 1 — canonicalization spike | not started | |
| Step 2 — decode pipeline | **in progress** — base45 done in Rust, green against the fixtures | 2026-10-24 |
| Step 3 — trust list + verification | not started | |
| Step 4 — SHLink legs | not started | |
| Step 5 — OpenAPI parity | not started | |
| Step 6 — cut over | not started | |

## Open questions

- **Which repo does the port land in?** Per `itb-plugins/docs/MIGRATION.md`,
  `gdhcn-helper/` is destined for `itb-plugin-hcert-decoder`, and that repo is
  to be requested under `WorldHealthOrganization`. So the port's target repo
  **does not exist yet** — the WHO repo request is upstream of this work.
- **The target repo is already polyglot.** `itb-plugin-hcert-decoder` carries a
  Node `dialect/` depending on `@opentestbed/otb-gherkin`. The service's
  language is therefore an independent choice from the dialect tooling; do not
  let "the repo is JS" or "the repo is Python" drive it.
- **Is the UI in scope?** `ui.html` and the React/Vite app (whose `package.json`
  is named `fhir-vite-mock`) are separate from the API. `tools/make-shlink.py`
  is a dev-time fixture generator, not service code, and can stay Python
  regardless.
- **`config/manifest.yaml`** has a hardcoded bundle with `pin: "1234"` — test
  scaffolding or production surface?
