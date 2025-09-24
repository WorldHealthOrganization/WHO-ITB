# GDHCN HCERT & SMART Health Link Validator

A compact REST API that:
- decodes EU DCC **HC1** strings (Base45 → zlib → CBOR → COSE),
- extracts **metadata** (issuer, KID),
- discovers and follows **SMART Health Link (SHLink)** pointers,
- authorizes with **PIN/passcode**, and
- **fetches FHIR** resources from a returned manifest.

It includes interactive API docs and is container-ready.

## Features

- **QR → Text**: Decode QR images to raw text (HC1, shlink, URL).
- **HC1 Decode**: Base45 → zlib → COSE/CBOR (COSE_Sign1).
- **Metadata**: Extract KID (base64url) and issuer from CWT/COSE.
- **SHLink**: Parse `hcert[5]` or pointer-style `payload[-260][5]`.
- **Authorization**: POST a PIN / passcode to obtain a manifest.
- **FHIR Fetch**: Download FHIR resources referenced by the manifest.
- **Docs**: ReDoc at `/docs` (read-only). Optional Swagger-UI at `/swagger` (Try it out).

---

## Quick Start

### Using Docker (recommended)

```bash
# Build image
docker build -t hcert-validator:latest .

# Run container (host port 9090 -> container 8080)
docker run --rm -p 9090:8080 --name hcert hcert-validator:latest
```

Open:
- API docs (ReDoc): `http://localhost:9090/docs`
- OpenAPI JSON: `http://localhost:9090/openapi.json`

> Want interactive “Try it out”? Enable the optional `/swagger` route (already in app if you kept it) and visit `http://localhost:9090/swagger`.

### Using Docker Compose

```bash
# Build & run
docker compose up --build -d

# Logs
docker compose logs -f
```

Make sure your compose file maps your desired **host** port to container **8080**, e.g.:
```yaml
services:
  hcert:
    build: .
    image: hcert-validator:latest
    ports:
      - "9090:8080"   # host:container
```

### Local Development

```bash
# System dependency for QR decoding (Debian/Ubuntu)
sudo apt-get update && sudo apt-get install -y libzbar0

# Python deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the API (listens on 0.0.0.0:8080)
python app.py
```

---

## API Overview

- `GET  /status` – service health & versions  
- `GET  /health` – alias of status  
- `POST /decode/image` – multipart; extract raw QR data  
- `POST /decode/hcert` – `{ "qr_data": "HC1:..." }` → COSE/CWT/HCERT  
- `POST /extract/metadata` – `{ cose, payload }` → issuer, kid  
- `POST /extract/reference` – `{ hcert? , payload? }` → SHLink (URL/key/flags/exp)  
- `POST /shlink/authorize` – `{ url, pin }` → manifest  
- `POST /shlink/fetch-fhir` – `{ manifest }` → FHIR resources  
- `GET  /docs` – ReDoc (pretty, read-only)  
- `GET  /swagger` – Swagger-UI (interactive), if enabled  
- `GET  /openapi.json` – OpenAPI 3.0 spec

> Default container port: **8080** (map to any host port you like).

---

## End-to-End Example (your real flow)

### 1) Decode QR image

```bash
curl -s -X POST http://localhost:9090/decode/image \
  -F "image=@qr_sample.png"
```

Example result:
```json
{
  "decoded": true,
  "format": "hcert",
  "qr_data": "HC1:6BFOXNMG2N9HZBPYHQ3D69SO5D6%9L60JO DJS4L:P:..."
}
```

### 2) Decode HCERT

```bash
curl -s -X POST http://localhost:9090/decode/hcert \
  -H "Content-Type: application/json" \
  -d '{
    "qr_data": "HC1:6BFOXNMG2N9HZBPYHQ3D69SO5D6%9L60JO DJS4L:P:..."
  }'
```

Example result (pointer-style CWT with SHLink):
```json
{
  "diagnostics": { "base45_decoded_len": 409, "zlib_decompressed_len": 406 },
  "cose": {
    "protected": { "1": -7, "4": "I1BAX8FATLs=" },
    "unprotected": {},
    "kid_b64": "I1BAX8FATLs=",
    "signature": "OK5Ba5glwnQjmHVj0YOsFPpB3uNG2GnZ3TS7K1hUorASAo56x95jSBCrwMIi2WanxrmBDemDxF6CUURDIbH9sQ"
  },
  "payload": {
    "1": "XJ",
    "4": 1745589915,
    "6": 1755625612038,
    "-260": {
      "5": [
        {
          "u": "shlink://eyJ1cmwiOiJodHRwOi8vbGFjcGFzcy5jcmVhdGUuY2w6ODE4Mi92Mi9tYW5pZmVzdHMvYmEwNzYxMWQtYjljOC00MTA0LWEwODYtNTU0ZDhiNmNjMDE0IiwiZmxhZyI6IlAiLCJleHAiOjE3NDU1ODk5MTU5NTMsImtleSI6InpURE9ETnRBTEktUXpuTXhKcGJqRFozeElLaEF2ZThQZ3I5VDFMODFMdVU9IiwibGFiZWwiOiJHREhDTiBWYWxpZGF0b3IifQ=="
        }
      ]
    }
  },
  "hcert": null
}
```

### 3) Extract metadata

```bash
curl -s -X POST http://localhost:9090/extract/metadata \
  -H "Content-Type: application/json" \
  -d '{
    "cose": { "protected": { "1": -7, "4": "I1BAX8FATLs=" }, "unprotected": {} },
    "payload": { "1": "XJ" }
  }'
```

Example:
```json
{ "issuer": "XJ", "kid": "I1BAX8FATLs=" }
```

### 4) Extract SHLink from payload

```bash
curl -s -X POST http://localhost:9090/extract/reference \
  -H "Content-Type: application/json" \
  -d '{
    "hcert": null,
    "payload": {
      "-260": {
        "5": [{
          "u": "shlink://eyJ1cmwiOiJodHRwOi8vbGFjcGFzcy5jcmVhdGUuY2w6..."
        }]
      }
    }
  }'
```

Example:
```json
{
  "hasReference": true,
  "url": "http://lacpass.create.cl:8182/v2/manifests/ba07611d-b9c8-4104-a086-554d8b6cc014",
  "key": "zTDODNtALI-QznMxJpbjDZ3xIKhAve8Pgr9T1L81LuU=",
  "flags": "P",
  "exp": 1745589915953
}
```

### 5) Authorize with PIN / passcode

```bash
curl -s -X POST http://localhost:9090/shlink/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://lacpass.create.cl:8182/v2/manifests/ba07611d-b9c8-4104-a086-554d8b6cc014",
    "pin": "1234"
  }'
```

Example:
```json
{
  "manifest": {
    "files": [
      {
        "contentType": "application/fhir+json",
        "location": "http://lacpass.create.cl:8182/v2/ips-json/ba07611d-b9c8-4104-a086-554d8b6cc014?key=b67e1488-b40b-4a79-b213-3dcad22cf1e4"
      }
    ]
  }
}
```

### 6) Fetch FHIR resources

```bash
curl -s -X POST http://localhost:9090/shlink/fetch-fhir \
  -H "Content-Type: application/json" \
  -d '{
    "manifest": {
      "files": [{
        "contentType": "application/fhir+json",
        "location": "http://lacpass.create.cl:8182/v2/ips-json/ba07611d-b9c8-4104-a086-554d8b6cc014?key=b67e1488-b40b-4a79-b213-3dcad22cf1e4"
      }]
    }
  }'
```

Typical success:
```json
{
  "found": true,
  "fhir": [
    {
      "url": "http://lacpass.create.cl:8182/v2/ips-json/ba07611d-b9c8-4104-a086-554d8b6cc014?key=b67e1488-b40b-4a79-b213-3dcad22cf1e4",
      "resource": { "resourceType": "Bundle", "type": "collection", "entry": [ { "resource": { "resourceType": "Patient" } } ] }
    }
  ],
  "errors": []
}
```

---

## Web UI

A simple HTML helper (`ui.html`) is included. Open it in a browser and set:
```js
const API_BASE = 'http://localhost:9090'; // or your host:port
```
It walks you through the full flow (decode → metadata → shlink → authorize → fetch FHIR).

---

## Configuration

- **Port**: The API listens on `0.0.0.0:8080`. Map it to any host port via Docker/Compose.
- **SERVICE_VERSION**: You can set `SERVICE_VERSION` env var to stamp the docs/status.
- **CORS**: Enabled (via `flask-cors`) for local browser testing.

---

## Troubleshooting

- **Container restarts with `NameError: SERVICE_VERSION`**  
  Ensure `SERVICE_VERSION` is defined **before** building the OpenAPI dict *or* injected at request time in `/openapi.json` (your app already handles this).
- **Spaces in HC1**  
  Space is valid Base45; the decoder **preserves** spaces. Don’t trim HC1.
- **No HCERT found**  
  Pointer-style QR codes put SHLink under `payload[-260][5]`, not `hcert[1][5]`. Your `/extract/reference` handles both.
- **FHIR fetch fails**  
  Verify outbound network access from the container. Endpoint must accept `Accept: application/fhir+json` (sent by the app). Manifests may use `files[].location` (supported).

---

## License

MIT

---

## References

- EU DCC / HCERT format  
- COSE / CBOR (IETF RFC 8152)  
- SMART Health Links (HL7 IG)  
- WHO SMART Trust ecosystem
