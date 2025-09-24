#!/usr/bin/env python3
import io
import json
import os
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from fastapi import FastAPI, Body, HTTPException, Header, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
from pydantic import BaseModel, Field
import yaml  # for /openapi.yaml

import logging
import base64

LOG_LEVEL = os.getenv("SMART_HELPER_LOG", "INFO").upper()
LOG_BODY_LIMIT = int(os.getenv("SMART_HELPER_LOG_BODY_LIMIT", "4000"))  # bytes shown

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("smart-helper")

# ---------- Config ----------
DEFAULT_FHIR_HOST = os.getenv("FHIR_HOST", "http://fhirserver:8080/fhir")          # plain FHIR (default)
DEFAULT_MATCHBOX_HOST = os.getenv("MATCHBOX_HOST", "http://matchbox:8080/matchboxv3/fhir")    # matchbox

DEFAULT_FHIR_TOKEN = os.getenv("FHIR_TOKEN")  # optional
DEFAULT_TIMEOUT = int(os.getenv("FHIR_TIMEOUT", "90"))

tags_metadata = [
    {"name": "Utils", "description": "Service health, target discovery, content extraction, and OpenAPI schema."},
    {"name": "IG", "description": "Implementation Guide installation: download IG package.tgz, extract, and upload resources in dependency order."},
    {"name": "Validation", "description": "Validate resources using FHIR `$validate` and return concise OperationOutcome issues."},
    {"name": "StructureMap", "description": "Mapping language endpoints: upload `.map` text, create JSON StructureMap, and execute `$transform`."},
]

app = FastAPI(
    title="SMART Helper",
    version="1.0.0",
    description=(
        "SMART Helper bridges ITB, Matchbox, and a plain FHIR server. "
        "It installs Implementation Guides, validates resources, converts Mapping Language to StructureMap, "
        "runs `$transform` (via Matchbox), and offers small utilities."
    ),
    openapi_tags=tags_metadata,
)

# ---------- Utilities ----------
def resolve_target_host(target: Optional[str]) -> str:
    """
    Resolve a short target name to a full base URL using env vars, with built-in defaults.
    - None / 'fhir' / 'default' -> FHIR_HOST or DEFAULT_FHIR_HOST
    - 'matchbox'                -> MATCHBOX_HOST or DEFAULT_MATCHBOX_HOST
    - any other 'X'             -> {X}_HOST env must exist
    """
    if target is None or target.lower() in ("fhir", "default"):
        return os.getenv("FHIR_HOST", DEFAULT_FHIR_HOST)
    if target.lower() == "matchbox":
        return os.getenv("MATCHBOX_HOST", DEFAULT_MATCHBOX_HOST)
    key = f"{target.upper()}_HOST"
    val = os.getenv(key)
    if val:
        return val
    raise HTTPException(status_code=400, detail=f"Unknown target '{target}'. Set env {key}=http://... first.")

def hdrs(accept: Optional[str] = None,
         content_type: Optional[str] = None,
         token: Optional[str] = None) -> Dict[str, str]:
    """Build standard FHIR HTTP headers (Accept, Content-Type, Authorization)."""
    h: Dict[str, str] = {}
    if accept:
        h["Accept"] = accept
    if content_type:
        h["Content-Type"] = content_type
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

def outcome_errors(oo: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract concise OperationOutcome issues with severity/code/location/details."""
    out: List[Dict[str, Any]] = []
    for i in (oo or {}).get("issue", []):
        sev = i.get("severity")
        code = i.get("code")
        locs = i.get("location") or i.get("expression") or []
        details = ((i.get("details") or {}).get("text")) or i.get("diagnostics")
        out.append({"severity": sev, "code": code, "location": locs, "details": details})
    return out

def fhir_request(method: str, url: str, token: Optional[str], *,
                 data: Optional[bytes] = None,
                 json_body: Optional[Dict[str, Any]] = None,
                 accept: str = "application/fhir+json",  # FIXED: Always use FHIR+JSON
                 content_type: Optional[str] = None,
                 timeout: int = DEFAULT_TIMEOUT,
                 params: Optional[Dict[str, Any]] = None) -> requests.Response:
    """Light wrapper over requests.request that sets FHIR headers and forwards query params."""
    headers = hdrs(accept=accept, content_type=content_type, token=token)

    if LOG_LEVEL in ("DEBUG", "TRACE"):
        # Show what we're about to send
        qp = ""
        if params:
            try:
                # best-effort preview, requests will encode properly
                qp = "?" + "&".join([f"{k}={v}" for k, v in params.items()])
            except Exception:
                qp = "?" + str(params)
        log.debug("OUT %s %s%s  accept=%s  content-type=%s", method, url, qp, accept, content_type)
        if json_body is not None:
            preview = json.dumps(json_body)[:LOG_BODY_LIMIT]
            log.debug("OUT json (snip):\n%s%s", preview, "…(snip)" if len(preview) == LOG_BODY_LIMIT else "")
        elif data is not None:
            log.debug("OUT data bytes=%s (snip):\n%s", len(data), _snip(data))
        else:
            log.debug("OUT (no body)")

    resp = requests.request(
        method, url, headers=headers, data=data, json=json_body, timeout=timeout, params=params
    )

    if LOG_LEVEL in ("DEBUG", "TRACE"):
        log.debug("IN<- %s %s  content-type=%s", resp.status_code, url, resp.headers.get("content-type"))
        # Try JSON first, then bytes
        try:
            j = resp.json()
            log.debug("IN<- json keys: %s", list(j.keys())[:12])
        except Exception:
            try:
                b = resp.content or b""
            except Exception:
                b = b""
            if b:
                log.debug("IN<- body (snip):\n%s", _snip(b))
    return resp

def is_success(resp: requests.Response) -> bool:
    return 200 <= resp.status_code < 300

def safe_json(resp: requests.Response) -> Optional[Dict[str, Any]]:
    try:
        return resp.json()
    except Exception:
        return None

def _snip(b: bytes, limit: int = LOG_BODY_LIMIT) -> str:
    try:
        s = b[:limit].decode("utf-8", errors="replace")
    except Exception:
        s = str(b[:limit])
    if len(b) > limit:
        s += f"\n…(snipped {len(b) - limit} bytes)"
    return s

def _ctype_is_json(ctype: str) -> bool:
    return (ctype or "").lower().startswith("application/json") or "fhir+json" in (ctype or "").lower()

# Posting order helps with dependencies
UPLOAD_ORDER = ["CodeSystem", "ValueSet", "StructureDefinition", "ConceptMap", "StructureMap"]

# ---------- Models ----------
class UploadIGRequest(BaseModel):
    """Body for /upload_ig endpoints: IG URL and optional target."""
    ig_url: str = Field(..., description="IG base URL or direct URL to `package.tgz`.", example="https://example.org/ig")
    target: Optional[str] = Field(None, description="Target server: 'fhir', 'matchbox', or custom. Defaults to 'fhir'.")

class ValidateRequest(BaseModel):
    """Validate a resource against a profile using FHIR `$validate`."""
    resource: Dict[str, Any] = Field(..., description="FHIR resource JSON to validate.")
    profile_url: str = Field(..., description="Canonical profile URL used as `?profile=`.")
    host: Optional[str] = Field(None, description="Override FHIR server base URL; defaults to `FHIR_HOST`.")
    token: Optional[str] = Field(None, description="Bearer token; defaults to `FHIR_TOKEN`.")
    include_warnings: bool = Field(False, description="Include warnings/info in the reported issues.")
    model_config = {
        "json_schema_extra": {
            "examples": [{
                "resource": {"resourceType": "Patient", "name": [{"family": "Doe", "given": ["John"]}]},
                "profile_url": "http://hl7.org/fhir/StructureDefinition/Patient"
            }]
        }
    }

class StructureMapTextRequest(BaseModel):
    """Send FHIR Mapping Language `.map` text and get back a JSON StructureMap."""
    text: str = Field(..., description="FHIR Mapping Language text content.")
    host: Optional[str] = Field(None, description="Override FHIR server base URL; defaults to `FHIR_HOST`.")
    token: Optional[str] = Field(None, description="Bearer token; defaults to `FHIR_TOKEN`.")
    model_config = {
        "json_schema_extra": {
            "examples": [{
                "text": "map \"http://ex/Map\" = 'Ex'\n group G(source s: Patient, target t: Patient) { }"
            }]
        }
    }

class ExtractRequest(BaseModel):
    """Utility to extract nested content by a list of keys."""
    envelope: Dict[str, Any] = Field(..., description="Input JSON envelope.")
    path: List[str] = Field(default_factory=lambda: ["-260", "-6"], description="Sequential keys to drill down.")
    model_config = {
        "json_schema_extra": {
            "examples": [{
                "envelope": {"-260": {"-6": {"n": "Cristina Rodriguez"}}},
                "path": ["-260", "-6"]
            }]
        }
    }

class ValidationIssue(BaseModel):
    severity: Optional[str] = Field(None, description="fatal | error | warning | information | note")
    code: Optional[str] = Field(None, description="Issue type code (from OperationOutcome).")
    location: List[str] = Field(default_factory=list, description="Locations/expressions related to the issue.")
    details: Optional[str] = Field(None, description="Human-readable details / diagnostics.")

class ValidateResponse(BaseModel):
    endpoint: str
    status: int
    ok: bool
    issues: List[ValidationIssue] = Field(default_factory=list)
    raw: Optional[Dict[str, Any]] = Field(default=None, description="Raw OperationOutcome if available.")

# ---------- Core helpers ----------
def download_package(ig_url: str, *, timeout: int = DEFAULT_TIMEOUT) -> bytes:
    url = ig_url if ig_url.endswith("package.tgz") else ig_url.rstrip("/") + "/package.tgz"
    r = requests.get(url, timeout=timeout, allow_redirects=True)
    if not is_success(r):
        raise HTTPException(status_code=502, detail=f"Failed to download package.tgz ({r.status_code})")
    if not r.content:
        raise HTTPException(status_code=502, detail="Downloaded package is empty")
    return r.content

def iter_package_files(pkg_bytes: bytes):
    with tarfile.open(fileobj=io.BytesIO(pkg_bytes), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            f = tf.extractfile(m)
            if not f:
                continue
            yield m.name, f.read()

def classify_file(path: str, data: bytes) -> Tuple[Optional[str], Optional[Any], Optional[str]]:
    """
    Returns (resourceTypeForUpload, parsedJsonOrText, sourceFormat)
    sourceFormat: "json", "map"
    """
    p = path.lower()

    # Plain text .map files
    if p.endswith(".map"):
        try:
            text = data.decode("utf-8")
        except Exception:
            text = data.decode("latin-1", errors="ignore")
        return "StructureMap", text, "map"

    # JSON files that might be FHIR resources
    if p.endswith(".json"):
        try:
            doc = json.loads(data.decode("utf-8"))
        except Exception:
            return None, None, None
        rt = doc.get("resourceType")
        if rt in {"StructureDefinition", "StructureMap", "ConceptMap", "ValueSet", "CodeSystem"}:
            return rt, doc, "json"

    return None, None, None

def post_json_resource(host: str, token: Optional[str], res_json: Dict[str, Any],
                       fhir_version_suffix: str = "4.0") -> Tuple[bool, Dict[str, Any]]:
    rt = res_json.get("resourceType")
    url = host.rstrip("/") + f"/{rt}"
    ct = f"application/fhir+json;fhirVersion={fhir_version_suffix}"
    resp = fhir_request("POST", url, token, json_body=res_json, content_type=ct, accept="application/fhir+json")
    ok = is_success(resp)
    body = safe_json(resp) or {"text": resp.text[:2000]}
    report = {
        "endpoint": url, "status": resp.status_code, "ok": ok,
        "resourceType": rt, "id": res_json.get("id"), "url": res_json.get("url"),
        "response": body
    }
    if not ok and body.get("resourceType") == "OperationOutcome":
        report["issues"] = outcome_errors(body)
    return ok, report

def post_map_text(host: str, token: Optional[str], text: str) -> Tuple[bool, Dict[str, Any]]:
    url = host.rstrip("/") + "/StructureMap"
    resp = fhir_request("POST", url, token, data=text.encode("utf-8"),
                        content_type="text/fhir-mapping", accept="application/fhir+json")
    ok = is_success(resp)
    body = safe_json(resp) or {"text": resp.text[:2000]}
    report = {"endpoint": url, "status": resp.status_code, "ok": ok, "response": body}
    if not ok and body.get("resourceType") == "OperationOutcome":
        report["issues"] = outcome_errors(body)
    return ok, report

def fhir_validate(host: str, token: Optional[str], resource: Dict[str, Any], profile_url: str,
                  include_warnings: bool = False) -> Dict[str, Any]:
    # Get resource type for resource-specific validation endpoint
    resource_type = resource.get("resourceType", "Resource")
    url = host.rstrip("/") + f"/{resource_type}/$validate"
    
    resp = fhir_request("POST", url, token, json_body=resource,
                        content_type="application/fhir+json", accept="application/fhir+json",  # FIXED: use fhir+json
                        params={"profile": profile_url})
    body = safe_json(resp) or {"text": resp.text[:2000]}
    issues: List[Dict[str, Any]] = []
    if body.get("resourceType") == "OperationOutcome":
        all_i = outcome_errors(body)
        issues = all_i if include_warnings else [i for i in all_i if i["severity"] in ("fatal", "error")]
    return {
        "endpoint": f"{url}?profile={profile_url}",
        "status": resp.status_code,
        "ok": is_success(resp),
        "issues": issues,
        "raw": body
    }

def fhir_transform_raw(host: str, token: Optional[str], source_url: str,
                       body_bytes: bytes, content_type: str):
    url = host.rstrip("/") + "/StructureMap/$transform"
    return fhir_request("POST", url, token, data=body_bytes, content_type=content_type,
                        accept="application/fhir+json", params={"source": source_url})

def fhir_validate_raw(host: str, token: Optional[str], body_bytes: bytes,
                      content_type: str, profile_url: str):
    url = host.rstrip("/") + "/$validate"
    return fhir_request("POST", url, token, data=body_bytes, content_type=content_type,
                        accept="application/fhir+json", params={"profile": profile_url})  # FIXED: use fhir+json

def _upload_ig_core(ig_url: str, host: str, token: Optional[str]):
    # 1) Download package.tgz
    try:
        pkg = download_package(ig_url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download error: {e}")

    # 2) Extract & classify
    by_type = {t: [] for t in UPLOAD_ORDER}
    skipped: List[str] = []
    errors: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []

    for path, data in iter_package_files(pkg):
        rt, payload, fmt = classify_file(path, data)
        if not rt:
            skipped.append(path)
            continue
        by_type[rt].append((path, payload, fmt))

    # 3) Upload in order
    for rt in UPLOAD_ORDER:
        for path, payload, fmt in by_type[rt]:
            if fmt == "json":
                ok, rep = post_json_resource(host, token, payload)
            elif fmt == "map":
                ok, rep = post_map_text(host, token, payload)
            else:
                ok, rep = False, {"status": 0, "ok": False, "error": "Unknown format"}
            rep["sourcePath"] = path
            rep["type"] = rt
            results.append(rep)
            if not ok:
                errors.append(rep)

    # 4) Summary
    return {
        "summary": {
            "host": host,
            "counts": {t: len(by_type[t]) for t in UPLOAD_ORDER},
            "uploaded": sum(1 for r in results if r.get("ok")),
            "failed": len(errors),
            "skippedFiles": skipped,
        },
        "results": results,
    }

def auth_token_from_header(authorization: Optional[str]) -> Optional[str]:
    """
    Accepts 'Authorization: Bearer <token>' or any value.
    Returns the token part for forwarding to the FHIR server.
    """
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return authorization

# ---------- Middleware ----------
@app.middleware("http")
async def _log_incoming(request: Request, call_next):
    if LOG_LEVEL in ("DEBUG", "TRACE"):
        try:
            body = await request.body()
        except Exception:
            body = b""
        log.debug(
            "IN %s %s  content-type=%s  len=%s",
            request.method, request.url.path + ("?" + request.url.query if request.url.query else ""),
            request.headers.get("content-type"), len(body),
        )
        if body:
            log.debug("IN body (snip):\n%s", _snip(body))
    return await call_next(request)

# ---------- Homepage ----------
@app.get("/", include_in_schema=False)
def home() -> HTMLResponse:
    """Human-friendly homepage for SMART Helper with quick links and service summary."""
    html = f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SMART Helper</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; line-height: 1.5; }}
    h1 {{ margin-top: 0; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 1100px; }}
    th, td {{ border: 1px solid #ddd; padding: .5rem .75rem; vertical-align: top; }}
    th {{ background: #f7f7f7; text-align: left; }}
    code {{ background: #f6f8fa; padding: 0 .25rem; border-radius: 3px; }}
    .links a {{ margin-right: 1rem; }}
    small.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: #666; }}
  </style>
</head>
<body>
  <h1>SMART Helper</h1>
  <p>
    SMART Helper bridges ITB, Matchbox, and a plain FHIR server. It can install IGs, validate resources,
    convert Mapping Language to StructureMap, run <code>$transform</code> (via Matchbox), and expose a few small utilities.
  </p>

  <p class="links">
    <a href="/docs">Swagger UI</a>
    <a href="/redoc">ReDoc</a>
    <a href="/openapi.yaml">OpenAPI (YAML)</a>
    <a href="/targets">/targets</a>
    <a href="/health">/health</a>
  </p>

  <h2>Services</h2>
  <table>
    <thead>
      <tr>
        <th>Endpoint</th>
        <th>Method</th>
        <th>What it does</th>
        <th>Backend</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>/upload_ig/{target}</code></td>
        <td>POST</td>
        <td>Download IG <code>package.tgz</code>, extract <em>CodeSystem → ValueSet → StructureDefinition → ConceptMap → StructureMap</em>, upload in order</td>
        <td>Path-based target (e.g. <code>/upload_ig/matchbox</code>)</td>
      </tr>
      <tr>
        <td><code>/upload_ig</code></td>
        <td>POST</td>
        <td>Download IG <code>package.tgz</code>, extract <em>CodeSystem → ValueSet → StructureDefinition → ConceptMap → StructureMap</em>, upload in order</td>
        <td>Direct URL (host field) or alias (target field) in JSON body</td>
      </tr>
      <tr>
        <td><code>/validate</code></td>
        <td>POST</td>
        <td>FHIR-native <code>$validate</code> against a profile; returns parsed OperationOutcome</td>
        <td>Default FHIR server (overridable in JSON body)</td>
      </tr>
      <tr>
        <td><code>/structuremap/text</code></td>
        <td>POST</td>
        <td>Upload Mapping Language <code>.map</code> text; returns the JSON <code>StructureMap</code></td>
        <td>Default FHIR server (overridable in JSON body)</td>
      </tr>
      <tr>
        <td><code>/transform</code></td>
        <td>POST</td>
        <td>Run <code>StructureMap/$transform</code> with raw JSON/XML; optionally validate the result</td>
        <td><strong>Matchbox</strong> (always)</td>
      </tr>
      <tr>
        <td><code>/extract</code></td>
        <td>POST</td>
        <td>Utility: extract nested content by key path from an envelope JSON</td>
        <td>—</td>
      </tr>
      <tr>
        <td><code>/echo</code></td>
        <td>POST</td>
        <td>Echo back headers and body for debugging ITB requests</td>
        <td>—</td>
      </tr>
      <tr>
        <td><code>/targets</code></td>
        <td>GET</td>
        <td>List configured targets (e.g. <code>fhir</code>, <code>matchbox</code>, and any <code>*_HOST</code>)</td>
        <td>—</td>
      </tr>
      <tr>
        <td><code>/health</code></td>
        <td>GET</td>
        <td>Liveness probe; shows default FHIR host</td>
        <td>—</td>
      </tr>
    </tbody>
  </table>

  <p><small class="mono">Defaults: FHIR_HOST = {DEFAULT_FHIR_HOST} · MATCHBOX_HOST = {DEFAULT_MATCHBOX_HOST}</small></p>
</body>
</html>
"""
    return HTMLResponse(html)

# ---------- Endpoints ----------
@app.get("/health", tags=["Utils"], summary="Liveness probe")
def health():
    """Return a simple liveness payload and the configured default FHIR host."""
    return {"status": "ok", "hostDefault": DEFAULT_FHIR_HOST}

@app.post("/echo", tags=["Utils"], summary="Echo back headers and body")
async def echo_endpoint(request: Request):
    """Echo back headers and body exactly as received (for debugging ITB requests)."""
    body = await request.body()
    try:
        parsed = json.loads(body) if body else None
    except Exception:
        parsed = None

    # Log to console
    log.info("=== /echo called ===")
    log.info("Headers: %s", dict(request.headers))
    log.info("Raw body: %s", body.decode("utf-8", errors="replace"))
    if parsed is not None:
        log.info("Parsed JSON: %s", json.dumps(parsed, indent=2))
    else:
        log.info("Body could not be parsed as JSON")

    return {
        "method": request.method,
        "url": str(request.url),
        "headers": dict(request.headers),
        "raw_body": body.decode("utf-8", errors="replace"),
        "json_body": parsed,
        "content_length": len(body),
        "is_valid_json": parsed is not None
    }

@app.get("/targets", tags=["Utils"], summary="List available upload targets")
def list_targets():
    """
    Returns the configured upload targets and their resolved base URLs.
    Always includes **fhir** and **matchbox**; any other `{NAME}_HOST` envs are included too.
    """
    targets = {
        "fhir": resolve_target_host("fhir"),
        "matchbox": resolve_target_host("matchbox"),
    }
    for k, v in os.environ.items():
        if k.endswith("_HOST") and k not in ("FHIR_HOST", "MATCHBOX_HOST"):
            name = k[:-5].lower()
            targets[name] = v
    return {"targets": targets}

@app.post(
    "/upload_ig",
    tags=["IG"],
    summary="Install a FHIR IG package by URL (JSON body only)",
)
def upload_ig(
    req: UploadIGRequest,
    authorization: Optional[str] = Header(None, description="Bearer token forwarded to the FHIR server"),
):
    """
    Downloads `package.tgz`, extracts CodeSystem/ValueSet/StructureDefinition/ConceptMap/StructureMap,
    uploads them to the specified target (default: 'fhir'), and returns a per-file report.
    
    **Body**: JSON with `ig_url` and optional `target`
    **Example**: `{"ig_url": "https://example.org/ig", "target": "matchbox"}`
    """
    target = req.target or "fhir"
    host = resolve_target_host(target).rstrip("/")
    token = auth_token_from_header(authorization) or DEFAULT_FHIR_TOKEN
    return _upload_ig_core(req.ig_url, host, token)

@app.post(
    "/validate",
    tags=["Validation"],
    summary="Validate a resource against a profile ($validate) - raw FHIR server response",
)
def validate_raw(req: ValidateRequest):
    """
    Validate a FHIR resource against a given profile using `$validate`.
    Returns the exact response from the FHIR server without any processing.
    """
    host = (req.host or DEFAULT_FHIR_HOST).rstrip("/")
    token = req.token or DEFAULT_FHIR_TOKEN
    
    try:
        # Get resource type for resource-specific validation endpoint
        resource_type = req.resource.get("resourceType", "Resource")
        url = host.rstrip("/") + f"/{resource_type}/$validate"
        
        resp = fhir_request("POST", url, token, json_body=req.resource,
                            content_type="application/fhir+json", accept="application/fhir+json",
                            params={"profile": req.profile_url})
        
        # Return exactly what the FHIR server returned
        try:
            return resp.json()
        except Exception:
            # If not JSON, return as text
            return {"text": resp.text, "status": resp.status_code}
            
    except Exception as e:
        # Only handle connection/server errors
        raise HTTPException(status_code=502, detail=f"FHIR server error: {str(e)}")

@app.post(
    "/validate_parse",
    tags=["Validation"],
    summary="Validate a resource against a profile ($validate) - parsed response",
    response_model=ValidateResponse,
)
def validate_parsed(req: ValidateRequest):
    """
    Validate a FHIR resource against a given profile using `$validate`.
    Returns parsed OperationOutcome issues (fatal/error by default; set `include_warnings=true` to include more).
    """
    host = (req.host or DEFAULT_FHIR_HOST).rstrip("/")
    token = req.token or DEFAULT_FHIR_TOKEN
    report = fhir_validate(host, token, req.resource, req.profile_url, include_warnings=req.include_warnings)
    return report

    
@app.post(
    "/structuremap/text",
    tags=["StructureMap"],
    summary="Create a StructureMap from FHIR Mapping Language text",
)
def structuremap_from_text(req: StructureMapTextRequest):
    """Posts `.map` text to `/StructureMap` and returns the FHIR server's JSON StructureMap (or OperationOutcome)."""
    host = (req.host or DEFAULT_FHIR_HOST).rstrip("/")
    token = req.token or DEFAULT_FHIR_TOKEN
    ok, rep = post_map_text(host, token, req.text)
    if not ok:
        raise HTTPException(status_code=502, detail=rep)
    return rep

@app.post(
    "/transform",
    tags=["StructureMap"],
    summary="Run StructureMap $transform with raw JSON or XML (Matchbox only)",
)
async def transform_simple(
    request: Request,
    source: str = Query(..., description="StructureMap canonical URL to use as `source`."),
    validateProfile: Optional[str] = Query(None, description="Optional profile canonical URL to validate the result."),
    debug: Optional[int] = Query(0, description="If 1, include request echo and upstream raw in response"),
):
    """
    Forward the raw body (JSON or XML) to Matchbox's `/StructureMap/$transform?source=...`.

    - **Body**: FHIR resource in JSON or XML
    - **Content-Type**: `application/fhir+json` or `application/fhir+xml`
    - Returns the transform result from Matchbox (JSON preferred).
    - If `validateProfile` is provided, also runs `$validate` on the transform result.
    """
    host = resolve_target_host("matchbox").rstrip("/")   # always Matchbox
    token = DEFAULT_FHIR_TOKEN

    body = await request.body()
    ctype_in = request.headers.get("content-type", "application/fhir+json")
    clen = len(body)

    # Debug logs
    log.info("TRANSFORM in: len=%s content-type=%s source=%s", clen, ctype_in, source)
    if LOG_LEVEL in ("DEBUG", "TRACE"):
        log.debug("TRANSFORM in body (snip):\n%s", _snip(body))

    if not body:
        # Fail fast with helpful message
        raise HTTPException(status_code=400, detail={
            "error": "Empty request body for /transform",
            "hint": "Ensure ITB sends a raw JSON string as body; see TemplateProcessor '${obj}' trick.",
            "receivedContentType": ctype_in
        })

    # 1) Transform - using proper FHIR headers
    resp = fhir_transform_raw(host, token, source, body, ctype_in)
    ok = is_success(resp)

    # Decode upstream (prefer JSON)
    result_body = safe_json(resp)
    if result_body is None:
        # If not JSON, pass short text to help debugging
        result_body = {"text": (resp.text or "")[:LOG_BODY_LIMIT]}
    if not ok:
        detail = {"upstreamStatus": resp.status_code, "upstream": result_body}
        # Some deployments wrap OO as base64 -> add friendly hint
        if isinstance(result_body, dict) and result_body.get("detail") and isinstance(result_body["detail"], str):
            try:
                decoded = base64.b64decode(result_body["detail"]).decode("utf-8", errors="replace")
                detail["detailDecoded"] = decoded[:LOG_BODY_LIMIT]
            except Exception:
                pass
        # Also attach what we sent (short)
        if debug:
            detail["echo"] = {
                "contentTypeIn": ctype_in,
                "lenIn": clen,
                "bodySnip": _snip(body),
                "to": host + "/StructureMap/$transform",
                "params": {"source": source}
            }
        raise HTTPException(status_code=502, detail=detail)

    out: Dict[str, Any] = {"ok": True, "result": result_body}

    # 2) Optional validation of transform result
    if validateProfile:
        if isinstance(result_body, dict):
            vresp = fhir_validate(host, token, result_body, validateProfile, include_warnings=False)
            out["validation"] = vresp
        else:
            vresp_raw = fhir_validate_raw(
                host, token, resp.content,
                resp.headers.get("content-type", "application/fhir+xml"),
                validateProfile
            )
            vbody = safe_json(vresp_raw) or {"text": (vresp_raw.text or "")[:LOG_BODY_LIMIT]}
            issues = outcome_errors(vbody) if vbody.get("resourceType") == "OperationOutcome" else []
            out["validation"] = {
                "endpoint": f"{host.rstrip('/')}/$validate?profile={validateProfile}",
                "status": vresp_raw.status_code,
                "ok": is_success(vresp_raw),
                "issues": [i for i in issues if i["severity"] in ("fatal", "error")],
                "raw": vbody
            }

    if debug:
        out["echo"] = {
            "contentTypeIn": ctype_in,
            "lenIn": clen,
            "bodySnip": _snip(body),
            "target": host + "/StructureMap/$transform",
            "params": {"source": source},
        }
    return out

@app.post(
    "/extract",
    tags=["Utils"],
    summary="Extract nested content by path keys",
)
def extract(req: ExtractRequest):
    """Walks the `envelope` by the given `path` of keys and returns the extracted value."""
    cur: Any = req.envelope
    for key in req.path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            raise HTTPException(status_code=400, detail=f"Path not found at {key}")
    return {"extracted": cur}

# ---------- OpenAPI as YAML (auto-generated) ----------
@app.get("/openapi.yaml", include_in_schema=False)
def openapi_yaml():
    """Return the auto-generated OpenAPI schema as YAML (no separate file needed)."""
    schema = app.openapi()
    return PlainTextResponse(yaml.safe_dump(schema, sort_keys=False), media_type="application/yaml")