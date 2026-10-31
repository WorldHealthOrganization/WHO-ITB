# SHLink test fixtures

The SHLink step of GDHCN verification is two HTTP calls, and they need
different mocks. Pick by what you are testing.

| | mocks | reachable from | covers failures? |
|---|---|---|---|
| **GitHub Pages fixture** (`pages/`) | the **upstream SHL server** that `/shlink/authorize` and `/shlink/fetch-fhir` call | anywhere, incl. inside the `hcert-validator` container | no |
| **Vite mock** (`vite.config.ts`) | the **helper's own API responses**, for the browser UI | localhost only | yes |

These are not interchangeable. See "Why the Vite mock is not an upstream
server" below.

## GitHub Pages fixture

### You supply the bundle

Bundles are test data, so none is committed. Before generating, put a FHIR
Bundle at `public/bundles/<id>.json` -- `<id>` defaulting to the bundle id in
[`config/manifest.yaml`](../config/manifest.yaml), which is also what the Vite
mock serves. **Synthetic data only**: GitHub Pages is public and
unauthenticated, and the generator copies the bundle into `pages/` verbatim.

Generate, pointing at wherever you will publish `pages/`:

```bash
python tools/make-shlink.py --base-url https://ORG.github.io/REPO
```

That writes `pages/` (commit it, or publish it as a Pages artifact):

```
pages/.nojekyll
pages/shl/<id>/manifest.json   # bare {"files":[{contentType,location}]}
pages/shl/<id>/shlink.txt      # the shlink:// URI for this fixture
pages/bundles/<id>.json        # the FHIR bundle that `location` points at
```

The committed fixture uses the placeholder `https://ORG.github.io/REPO`;
re-run the generator with your real base URL before publishing. The script
prints ready-to-paste `curl` commands for all three steps.

### Two constraints to know

**A PIN is mandatory.** Pages serves GET/HEAD and answers POST with 405.
`/shlink/authorize` ([app.py:806](../app.py#L806)) only falls back to
`GET {url}?passcode=...` when a PIN is supplied; without one its sole
attempt is a POST, so it fails with `authorization_failed`. Counter-
intuitively, a PIN-protected SHLink is the *easier* one to simulate here.
The fixture therefore sets `flag: "P"`.

**The PIN is not enforced.** Pages serves the static manifest for any
passcode, including a wrong one. Negative tests need the Vite mock.

### Manifest shape

`manifest.json` must contain **bare** `{"files": [...]}`.
`/shlink/authorize` wraps whatever it receives as `{"manifest": ...}`
([app.py:861](../app.py#L861)), so a file that already has a `manifest` key
double-wraps and `/shlink/fetch-fhir` then collects zero URLs and returns
`found: false`.

### Other notes

- No JWE anywhere. This implementation never decrypts, so bundles are
  served as cleartext FHIR JSON. Real SHL files are JWE-encrypted under the
  SHLink `key`; the `key` in the generated payload is cosmetic.
- Fetching happens server-side from the container, so CORS is irrelevant
  (Pages sends `Access-Control-Allow-Origin: *` anyway, so the browser UI
  works too).
- `exp` is emitted in **seconds** per the SHL spec. The main README's
  example shows milliseconds; `app.py` passes `exp` through without
  interpreting it, so both "work".
- Pages is public and unauthenticated: **synthetic bundles only**. They also
  accumulate in the publishing branch's history.

## Vite mock

```bash
npm install
PUBLIC_BASE=http://localhost:5173 npx vite --port 5173
```

Driven by [`config/manifest.yaml`](../config/manifest.yaml) (bundle id, PIN,
file key) and serves bundles from `public/bundles/<id>.json`. It implements:

- `GET|POST /v2/manifests/:id` — PIN from JSON body, `?pin=`/`?passcode=`,
  or `X-Pin`/`X-Passcode`; compared with `timingSafeEqual`
- `GET /v2/ips-json/:id?key=...` — enforces the file key
- `GET /__ping` — liveness

Every failure returns an identical 404 `{"error":"not_available"}` so the
mock leaks nothing about which check failed.

### Why the Vite mock is not an upstream server

Both its endpoints return the **helper API's response envelopes**, not the
upstream wire shapes, because its job is to let the React UI run without the
Python backend:

- `/v2/manifests/:id` returns `{"manifest":{"files":[...]}}` — already
  wrapped, so through `/shlink/authorize` it double-wraps.
- `/v2/ips-json/:id` returns `{"found":true,"fhir":[...]}` — which has
  neither `resourceType` nor `entry`, so `/shlink/fetch-fhir` files it under
  `data` instead of `resource` ([app.py:920](../app.py#L920)).

To drive the Python service from this mock you would need variant endpoints
returning the bare shapes.

### Dependency pin

`package.json` pinned `vite: ^8.0.8` while `@vitejs/plugin-react@^4.3.1`
supports only vite ^4–^7, so `npm install` failed outright. Pinned to
`vite: ^7.0.0`. Bump both together if you want vite 8.
