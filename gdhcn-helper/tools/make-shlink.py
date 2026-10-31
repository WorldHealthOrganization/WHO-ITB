#!/usr/bin/env python3
"""Generate a GitHub Pages SHLink fixture: static manifest + bundle + shlink:// URI.

Only the happy path can be simulated on Pages: it serves GET/HEAD and answers
POST with 405, so the manifest is reachable only via /shlink/authorize's
`GET {url}?passcode=...` fallback -- which is attempted only when a PIN is
supplied. The PIN is therefore NOT enforced; any value is accepted. Use the
Vite mock in vite.config.ts for PIN/key enforcement and failure paths.

Usage:
    python tools/make-shlink.py --base-url https://ORG.github.io/REPO
"""

import argparse
import base64
import json
import pathlib
import shutil
import time

DEFAULT_ID = "ba07611d-b9c8-4104-a086-554d8b6cc014"
# Matches config/manifest.yaml so the same fixture drives the Vite mock.
DEFAULT_FILE_KEY = "933bd441-158c-4888-95ac-4465530fa717"
# Cosmetic here: this implementation never decrypts, so no JWE key is needed.
# Kept well-formed (32 bytes, base64url, unpadded) so it looks like a real SHL key.
DEFAULT_SHL_KEY = "zTDODNtALI-QznMxJpbjDZ3xIKhAve8Pgr9T1L81LuU"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def main() -> None:
    repo = pathlib.Path(__file__).resolve().parent.parent

    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True,
                    help="Pages root, e.g. https://ORG.github.io/REPO (no trailing slash)")
    ap.add_argument("--id", default=DEFAULT_ID)
    ap.add_argument("--pin", default="1234")
    ap.add_argument("--key", default=DEFAULT_SHL_KEY, help="SHL key in the shlink:// payload")
    ap.add_argument("--file-key", default=DEFAULT_FILE_KEY, help="key= query param on the file URL")
    ap.add_argument("--exp-days", type=int, default=365)
    ap.add_argument("--label", default="WHO-ITB Synthetic Test Bundle")
    ap.add_argument("--pages-dir", default=None)
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    pages = pathlib.Path(args.pages_dir) if args.pages_dir else repo / "pages"
    src_bundle = repo / "public" / "bundles" / (args.id + ".json")
    if not src_bundle.exists():
        raise SystemExit(
            "no bundle at " + str(src_bundle) + " -- bundles are test data "
            "and are deliberately not committed. Put a synthetic FHIR Bundle "
            "there (Pages is public and unauthenticated), or pass --id to name "
            "one you already have. See tools/README.md."
        )

    manifest_url = base + "/shl/" + args.id + "/manifest.json"
    file_url = base + "/bundles/" + args.id + ".json?key=" + args.file_key

    # Bare {"files": [...]}. /shlink/authorize wraps its response as
    # {"manifest": ...}, so a `manifest` key here would double-wrap and
    # /shlink/fetch-fhir would then find no files.
    manifest = {"files": [{"contentType": "application/fhir+json", "location": file_url}]}

    (pages / "shl" / args.id).mkdir(parents=True, exist_ok=True)
    (pages / "bundles").mkdir(parents=True, exist_ok=True)
    (pages / "shl" / args.id / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    shutil.copyfile(src_bundle, pages / "bundles" / (args.id + ".json"))
    (pages / ".nojekyll").write_text("", encoding="utf-8")

    # exp in seconds per the SHL spec (NumericDate). Note the README example
    # shows milliseconds; this app passes exp through without interpreting it.
    payload = {
        "url": manifest_url,
        "flag": "P",          # P = passcode required; also what enables the GET fallback
        "exp": int(time.time()) + args.exp_days * 86400,
        "key": args.key,
        "label": args.label,
    }
    shlink = "shlink://" + b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    (pages / "shl" / args.id / "shlink.txt").write_text(
        shlink + "\n", encoding="utf-8", newline="\n")

    api = "http://localhost:8089"
    hdr = '-H "Content-Type: application/json"'
    ref_body = json.dumps({"hcert": {"5": shlink}})
    auth_body = json.dumps({"url": manifest_url, "pin": args.pin})
    fetch_body = json.dumps({"manifest": manifest})

    print("Wrote " + str(pages))
    print()
    print("SHLink URI:")
    print(shlink)
    print()
    print("1) Parse the SHLink (expects hcert entry 5):")
    print("curl -s -X POST " + api + "/extract/reference " + hdr + " -d '" + ref_body + "'")
    print()
    print("2) Resolve the manifest (a PIN is required to reach the GET fallback):")
    print("curl -s -X POST " + api + "/shlink/authorize " + hdr + " -d '" + auth_body + "'")
    print()
    print("3) Fetch the FHIR bundle:")
    print("curl -s -X POST " + api + "/shlink/fetch-fhir " + hdr + " -d '" + fetch_body + "'")


if __name__ == "__main__":
    main()
