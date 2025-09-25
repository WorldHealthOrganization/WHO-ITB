#!/usr/bin/env python3
"""
GDHCN HCERT & SMART Health Link Validator Service with Signature Verification
Implements REST API for validating HCERT QR codes, verifying signatures via GDHCN trustlists,
and following SHLink references.
"""

import argparse
import base64
import hashlib
import io
import json
import logging
import platform
import re
import sys
import unicodedata
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import os

import base45
import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from jwcrypto import jwk, jws
from PIL import Image
from pyld import jsonld
from pyzbar import pyzbar

SERVICE_NAME = "GDHCN HCERT & SHLink Validator"
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "2.0.0")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Base45 alphabet
BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

# -------- JSON-LD context handling --------
REQUIRED_CONTEXT_URLS = {
    "https://www.w3.org/ns/did/v1": "did-v1.jsonld",
    "https://w3id.org/security/suites/jws-2020/v1": "jws-2020-v1.jsonld",
    "https://w3id.org/security/v2": "security-v2.jsonld",
    "https://worldhealthorganization.github.io/smart-trust/tng-additional-context/v1": "tng-additional-context-v1.jsonld",
}

REMOTE_CONTEXT_OVERRIDES = {
    "https://w3id.org/security/suites/jws-2020/v1": [
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
    ],
    "https://worldhealthorganization.github.io/smart-trust/tng-additional-context/v1": [
        "https://raw.githubusercontent.com/WorldHealthOrganization/smart-trust/tng-additional-context-jsonld/input/images/tng-additional-context/v1",
        "https://raw.githubusercontent.com/WorldHealthOrganization/smart-trust/main/tng-additional-context/v1.jsonld",
        "https://worldhealthorganization.github.io/smart-trust/tng-additional-context/v1",
    ],
}

# GDHCN environment bases
ENV_BASE = {
    "prod": "https://tng-cdn.who.int",
    "uat": "https://tng-cdn-uat.who.int",
    "dev": "https://tng-cdn-dev.who.int",
}

def fetch_remote_json(url: str) -> dict:
    """Fetch a JSON/JSON-LD document with friendly fallbacks."""
    headers = {"Accept": "application/ld+json, application/json;q=0.9, */*;q=0.1"}
    candidates = REMOTE_CONTEXT_OVERRIDES.get(url, [url])
    last_err = None
    
    for eff_url in candidates:
        try:
            resp = requests.get(eff_url, timeout=25, headers=headers, allow_redirects=True)
            resp.raise_for_status()
            try:
                return resp.json()
            except Exception:
                return json.loads(resp.text)
        except Exception as e:
            last_err = e
            continue

    if "tng-additional-context" in url:
        logger.warning("WHO extra context not reachable as JSON; using a no-op context.")
        return {"@context": {}}

    raise ValueError(f"Remote context fetch failed for {url}: {last_err}")

def make_local_context_loader(context_dir: str, allow_remote: bool = False):
    """Returns a function compatible with pyld.jsonld.set_document_loader."""
    pathmap = {url: os.path.join(context_dir, fname)
               for url, fname in REQUIRED_CONTEXT_URLS.items()}

    def loader(url: str, options=None):
        if url in pathmap and os.path.exists(pathmap[url]):
            with open(pathmap[url], "r", encoding="utf-8") as f:
                doc = json.load(f)
            return {"contextUrl": None, "documentUrl": url, "document": doc}

        if allow_remote:
            doc = fetch_remote_json(url)
            return {"contextUrl": None, "documentUrl": url, "document": doc}

        raise FileNotFoundError(
            f"Missing JSON-LD context for {url}. "
            f"Put it under {context_dir} or use allow_remote_contexts=true."
        )
    
    return loader

def canonicalize_without_proof(did_doc: dict, loader) -> bytes:
    """Remove 'proof' and normalize with URDNA2015 to N-Quads."""
    doc_wo_proof = {k: v for k, v in did_doc.items() if k != "proof"}
    nquads = jsonld.normalize(
        doc_wo_proof,
        {
            "algorithm": "URDNA2015",
            "format": "application/n-quads",
            "processingMode": "json-ld-1.1",
            "documentLoader": loader,
        },
    )
    return nquads.encode("utf-8")

# -------- Utility functions --------

def get_library_versions() -> Dict[str, str]:
    """Get versions of key libraries."""
    versions = {}
    try:
        import PIL
        versions['pillow'] = PIL.__version__
    except:
        versions['pillow'] = 'unknown'
    
    try:
        versions['flask'] = '2.3.3'  # Flask doesn't expose __version__ easily
    except:
        versions['flask'] = 'unknown'
    
    try:
        versions['cbor2'] = cbor2.__version__
    except:
        versions['cbor2'] = 'unknown'
    
    try:
        versions['pyzbar'] = '0.1.9'  # pyzbar doesn't expose version
    except:
        versions['pyzbar'] = 'unknown'
    
    try:
        versions['base45'] = '0.4.4'  # base45 doesn't expose version
    except:
        versions['base45'] = 'unknown'
    
    try:
        import cryptography
        versions['cryptography'] = cryptography.__version__
    except:
        versions['cryptography'] = 'unknown'
    
    try:
        import jwcrypto
        versions['jwcrypto'] = jwcrypto.__version__ if hasattr(jwcrypto, '__version__') else 'installed'
    except:
        versions['jwcrypto'] = 'unknown'
    
    try:
        import pyld
        versions['pyld'] = pyld.__version__ if hasattr(pyld, '__version__') else 'installed'
    except:
        versions['pyld'] = 'unknown'
    
    return versions

def normalize_text(text: str) -> Tuple[str, List[Dict]]:
    """Normalize text for processing."""
    text = unicodedata.normalize('NFKC', text)
    removed_chars = []
    
    hidden_chars = [
        '\u00A0', '\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060',
    ]
    
    for char in hidden_chars:
        if char in text:
            removed_chars.append({
                'char': f'U+{ord(char):04X}',
                'name': unicodedata.name(char, 'UNKNOWN')
            })
            text = text.replace(char, '')
    
    text_clean = re.sub(r'[\r\n\t]+', '', text)
    return text_clean, removed_chars

def sanitize_base45(text: str) -> Tuple[str, List[Dict]]:
    """Sanitize Base45 input by removing invalid characters."""
    invalid_chars = []
    clean_text = []
    
    for i, char in enumerate(text):
        if char in BASE45_ALPHABET:
            clean_text.append(char)
        else:
            invalid_chars.append({
                'index': i,
                'char': char,
                'unicode': f'U+{ord(char):04X}'
            })

    return ''.join(clean_text), invalid_chars

def unwrap_cbor_tags(data: Any) -> Any:
    """Recursively unwrap CBOR tags until we get to the actual data."""
    while isinstance(data, cbor2.CBORTag):
        logger.info(f"Unwrapping CBOR Tag {data.tag}")
        data = data.value
    return data

def bytes_to_json_safe(obj: Any) -> Any:
    """Convert bytes to base64url for JSON serialization."""
    if isinstance(obj, bytes):
        return {'_b64': base64.urlsafe_b64encode(obj).decode('ascii').rstrip('=')}
    elif isinstance(obj, dict):
        return {k: bytes_to_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [bytes_to_json_safe(item) for item in obj]
    return obj

# -------- COSE/Signature verification functions --------

def decode_cose_sign1(data: bytes) -> Dict[str, Any]:
    """Decode COSE_Sign1 structure."""
    cbor_data = cbor2.loads(data)
    cbor_data = unwrap_cbor_tags(cbor_data)
    
    if not isinstance(cbor_data, list) or len(cbor_data) != 4:
        raise ValueError(f"Invalid COSE_Sign1 structure: expected 4-element list, got {type(cbor_data)} with {len(cbor_data) if isinstance(cbor_data, list) else 'N/A'} elements")
    
    protected_bstr, unprotected_map, payload_bstr, signature_bstr = cbor_data
    
    protected_headers = {}
    if protected_bstr:
        protected_headers = cbor2.loads(protected_bstr)
        protected_headers_json = bytes_to_json_safe(protected_headers)  # reuse your helper
    
    payload = {}
    if payload_bstr:
        payload = cbor2.loads(payload_bstr)
    
    return {
        'protected': protected_headers,
        'protected_bstr': protected_bstr,
        'unprotected': unprotected_map or {},
        'payload': payload,
        'payload_bstr': payload_bstr,
        'signature': signature_bstr,
        'signature_b64': base64.urlsafe_b64encode(signature_bstr).decode('ascii').rstrip('=') if signature_bstr else None
    }

def extract_kid(cose_headers: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Extract KID from COSE headers. Returns (kid_b64, kid_hex)."""
    def find_kid(hdrs: Dict[str, Any]) -> Optional[Any]:
        return hdrs.get(4) or hdrs.get('4') if isinstance(hdrs, dict) else None

    kid = find_kid(cose_headers.get('protected', {})) or find_kid(cose_headers.get('unprotected', {}))
    
    if isinstance(kid, bytes):
        kid_b64 = base64.urlsafe_b64encode(kid).decode('ascii').rstrip('=')
        kid_hex = kid.hex()
        return kid_b64, kid_hex
    elif isinstance(kid, dict) and '_b64' in kid:
        return kid['_b64'], None
    elif isinstance(kid, str):
        return kid, None
    
    return None, None

def verify_es256(public_key, protected_bstr: bytes, payload_bstr: bytes, signature: bytes):
    """Verify ES256 COSE signature - matches CLI script exactly."""
    # Build Sig_structure
    sig_structure = ["Signature1", protected_bstr, b"", payload_bstr]
    to_be_signed = cbor2.dumps(sig_structure, canonical=True)
    
    # Convert raw r||s to DER for cryptography
    if len(signature) % 2 != 0:
        raise ValueError(f"Unexpected ECDSA signature length: {len(signature)}")
    half = len(signature) // 2
    r = int.from_bytes(signature[:half], "big")
    s = int.from_bytes(signature[half:], "big")
    der_sig = encode_dss_signature(r, s)
    
    # Verify - let exception propagate like in CLI
    public_key.verify(der_sig, to_be_signed, ec.ECDSA(hashes.SHA256()))

def pubkey_from_jwk_ec_p256(jwk_dict: dict):
    """Extract EC P-256 public key from JWK."""
    # Prefer x5c if present
    x5c = jwk_dict.get("x5c")
    if x5c:
        try:
            leaf_der = base64.b64decode(x5c[0])
            cert = x509.load_der_x509_certificate(leaf_der)
            return cert.public_key()
        except Exception:
            pass
    
    # Fall back to x/y coordinates
    if jwk_dict.get("kty") != "EC" or jwk_dict.get("crv") not in ("P-256", "secp256r1"):
        return None
    
    def b64u_to_bytes(s: str) -> bytes:
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s)
    
    x = int.from_bytes(b64u_to_bytes(jwk_dict["x"]), "big")
    y = int.from_bytes(b64u_to_bytes(jwk_dict["y"]), "big")
    curve = ec.SECP256R1()
    return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()

# -------- DID/Trustlist functions --------

def did_web_to_url(did: str) -> str:
    """Convert did:web identifier to HTTPS URL."""
    assert did.startswith("did:web:"), f"Unsupported DID method: {did}"
    parts = did[len("did:web:"):].split(":")
    host = parts[0]
    path = "/".join(parts[1:])
    if path:
        return f"https://{host}/{path}/did.json"
    else:
        return f"https://{host}/.well-known/did.json"

def build_trustlist_did(env: str, domain: str, participant: str, usage: str) -> str:
    """Build trustlist DID."""
    base_host = ENV_BASE[env].replace("https://", "")
    return f"did:web:{base_host}:v2:trustlist:{domain}:{participant}:{usage}"

def fetch_json(url: str) -> dict:
    """Fetch JSON from URL."""
    r = requests.get(url, timeout=25)
    r.raise_for_status()
    return r.json()

def dereference_verification_method(did_or_didurl: str) -> Tuple[dict, dict]:
    """Return (signer_did_document, verification_method_obj)."""
    if "#" in did_or_didurl:
        did, _ = did_or_didurl.split("#", 1)
        vm_id = did_or_didurl
    else:
        did = did_or_didurl
        vm_id = None

    did_doc = fetch_json(did_web_to_url(did))
    vms = did_doc.get("verificationMethod", [])

    if vm_id:
        for vm in vms:
            if vm.get("id") == vm_id:
                return did_doc, vm
        raise ValueError(f"verificationMethod not found: {vm_id}")

    # Otherwise, try assertionMethod/authentication references
    vm_map = {vm.get("id"): vm for vm in vms}
    for ref_group in ("assertionMethod", "authentication"):
        for ref in did_doc.get(ref_group, []) or []:
            if isinstance(ref, str) and ref in vm_map:
                return did_doc, vm_map[ref]
            if isinstance(ref, dict) and ref.get("id") in vm_map:
                return did_doc, vm_map[ref["id"]]
    
    if vms:
        return did_doc, vms[0]
    
    raise ValueError("No verificationMethod available in signer DID")

def verify_jsonwebsignature2020(did_doc: dict, loader) -> Tuple[str, str]:
    """Verify JsonWebSignature2020 proof on a DID document."""
    proof = did_doc.get("proof")
    if not proof or proof.get("type") != "JsonWebSignature2020":
        raise ValueError("DID doc has no JsonWebSignature2020 proof")

    jws_compact = proof.get("jws")
    if not isinstance(jws_compact, str) or jws_compact.count(".") != 2:
        raise ValueError("Invalid JWS compact in proof")

    vm_ref = proof.get("verificationMethod")
    if not vm_ref:
        raise ValueError("Missing verificationMethod in proof")

    _, vm = dereference_verification_method(vm_ref)
    vm_jwk = vm.get("publicKeyJwk")
    if not vm_jwk:
        raise ValueError("verificationMethod has no publicKeyJwk")

    payload = canonicalize_without_proof(did_doc, loader)

    jwk_obj = jwk.JWK(**vm_jwk)
    sig = jws.JWS()
    sig.deserialize(jws_compact)
    sig.verify(jwk_obj, detached_payload=payload)

    # Parse protected header
    header_b64 = jws_compact.split(".", 2)[0]
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    return vm.get("id", vm_ref), header.get("alg", "unknown")

def extract_pubkeys_from_trustlist_doc(doc: dict) -> List[Tuple[Optional[str], object]]:
    """Extract public keys from trustlist DID document."""
    keys = []
    for vm in doc.get("verificationMethod", []):
        jwk_obj = vm.get("publicKeyJwk")
        if not jwk_obj:
            continue
        pk = pubkey_from_jwk_ec_p256(jwk_obj)
        if pk is not None:
            keys.append((jwk_obj.get("kid"), pk))
    return keys

def parse_shlink_reference(hcert: Dict[str, Any]) -> Dict[str, Any]:
    """Parse SHLink/VHL reference from HCERT entry 5."""
    ref = hcert.get(5) or hcert.get('5')
    
    if not ref:
        return {'hasReference': False}
    
    result = {'hasReference': True, 'raw': ref}
    
    if isinstance(ref, bytes):
        ref = ref.decode('utf-8')
    
    if not isinstance(ref, str):
        return {'hasReference': False}
    
    if ref.startswith('shlink://'):
        payload_b64 = ref[9:]
        try:
            payload_json = base64.urlsafe_b64decode(payload_b64 + '=' * (4 - len(payload_b64) % 4))
            payload = json.loads(payload_json)
            
            result.update({
                'url': payload.get('url'),
                'key': payload.get('key'),
                'flags': payload.get('flag') or payload.get('flags'),
                'exp': payload.get('exp'),
                'raw': payload
            })
        except Exception as e:
            logger.error(f"Failed to decode shlink:// payload: {e}")
            result['error'] = str(e)
    elif not ref.startswith('http'):
        try:
            decoded = base64.urlsafe_b64decode(ref + '=' * (4 - len(ref) % 4))
            decoded_str = decoded.decode('utf-8')
            if decoded_str.startswith('http'):
                result['url'] = decoded_str
        except:
            result['url'] = ref
    else:
        result['url'] = ref
    
    return result

def extract_issuer(payload: Dict[str, Any]) -> Optional[str]:
    """Extract issuer from COSE payload."""
    issuer = payload.get('iss') or payload.get(1) or payload.get('1')
    return issuer if isinstance(issuer, str) else None

# -------- Original API Endpoints --------

@app.route('/status', methods=['GET'])
@app.route('/health', methods=['GET'])
def status():
    """Service status endpoint."""
    return jsonify({
        'service': SERVICE_NAME,
        'version': SERVICE_VERSION,
        'ready': True,
        'python': sys.version.split()[0],
        'platform': platform.platform(),
        'libraries': get_library_versions()
    })

@app.route('/decode/image', methods=['POST'])
def decode_image():
    """Decode QR code from image."""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'no_image', 'details': 'No image file provided'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'no_filename', 'details': 'No file selected'}), 400
        
        image = Image.open(io.BytesIO(file.read()))
        if image.mode != 'L':
            image = image.convert('L')
        
        decoded_objects = pyzbar.decode(image)
        
        if not decoded_objects:
            return jsonify({
                'decoded': False,
                'errors': ['No QR code found in image']
            })
        
        qr = decoded_objects[0]
        raw_bytes = qr.data
        if raw_bytes.startswith(b'HC1:') or raw_bytes.startswith(b'shlink://') or raw_bytes.startswith(b'http'):
            qr_data = raw_bytes.decode('utf-8')
        else:
            qr_data = raw_bytes.hex()
            
        normalized_data, removed_chars = normalize_text(qr_data)
        
        format_type = 'unknown'
        if normalized_data.startswith('HC1:'):
            format_type = 'hcert'
        elif normalized_data.startswith('shlink://'):
            format_type = 'shlink'
        elif normalized_data.startswith('http'):
            format_type = 'url'
        
        response = {
            'decoded': True,
            'format': format_type,
            'qr_data': normalized_data
        }
        
        if removed_chars:
            response['normalization_note'] = f"Removed {len(removed_chars)} hidden characters"
            response['removed_chars'] = removed_chars
        
        return jsonify(response)
        
    except Exception as e:
        logger.exception("Error decoding image")
        return jsonify({
            'error': 'decode_failed',
            'details': str(e),
            'decoded': False
        }), 400

@app.route('/decode/hcert', methods=['POST'])
def decode_hcert():
    """Decode HCERT data from HC1 format."""
    try:
        data = request.get_json()
        if not data or 'qr_data' not in data:
            return jsonify({'error': 'missing_qr_data', 'details': 'qr_data field required'}), 400

        qr_data = data['qr_data']
        logger.info(f"[hcert] Raw input length={len(qr_data)}")

        qr_data, norm_chars = normalize_text(qr_data)
        
        if qr_data.startswith('<!DOCTYPE html') or qr_data.startswith('<html'):
            return jsonify({
                'error': 'html_received_instead_of_hc1',
                'details': 'Server received HTML, not an HC1 string. Check API_BASE/port or proxy.',
                'hint': 'Ensure the frontend is posting to your Flask API, not a static web server.'
            }), 400
        
        if not qr_data.startswith('HC1:'):
            return jsonify({
                'error': 'invalid_format',
                'details': 'Data must start with HC1:',
                'received_prefix': qr_data[:10] if len(qr_data) > 10 else qr_data
            }), 400

        hc1_data = qr_data[4:]
        sanitized_data, invalid_chars = sanitize_base45(hc1_data)

        try:
            compressed_data = base45.b45decode(sanitized_data)
            logger.info(f"[hcert] Base45 decoded bytes={len(compressed_data)} preview={compressed_data[:20]!r}")
        except Exception as e:
            logger.warning(f"[hcert] Base45 decode failed: {e}")
            return jsonify({
                'error': 'base45_decode_failed',
                'details': str(e)
            }), 400

        try:
            cbor_data = zlib.decompress(compressed_data)
            logger.info(f"[hcert] zlib decompressed bytes={len(cbor_data)} preview={cbor_data[:20]!r}")
        except Exception as e:
            logger.warning(f"[hcert] zlib decompress failed: {e}")
            return jsonify({'error': 'zlib_decompress_failed', 'details': str(e)}), 400

        try:
            cose = decode_cose_sign1(cbor_data)
            logger.info(f"[hcert] COSE decoded: keys={list(cose.keys())}")
        except Exception as e:
            logger.warning(f"[hcert] COSE decode failed: {e}")
            return jsonify({
                'error': 'cose_decode_failed',
                'details': str(e),
                'repr_preview': repr(cbor_data[:100]) if len(cbor_data) > 100 else repr(cbor_data)
            }), 400

        payload = cose.get('payload', {}) or {}
        hcert = None
        if -260 in payload:
            container = payload[-260]
            if isinstance(container, dict) and 1 in container:
                hcert = container[1]
                logger.info("[hcert] Extracted HCERT (-260/1)")

        kid_b64, kid_hex = extract_kid({'protected': cose['protected'], 'unprotected': cose['unprotected']})
        if kid_b64:
            logger.info(f"[hcert] KID (b64url)={kid_b64}")

        response = {
            'diagnostics': {
                'base45_decoded_len': len(compressed_data),
                'zlib_decompressed_len': len(cbor_data),
            },
            'cose': {
                'protected': bytes_to_json_safe(cose['protected']),
                'unprotected': bytes_to_json_safe(cose['unprotected']),
                'kid_b64': kid_b64,
                'kid_hex': kid_hex,
                'signature': cose.get('signature_b64'),
            },
            'payload': bytes_to_json_safe(payload),
            'hcert': bytes_to_json_safe(hcert) if hcert is not None else None
        }
        
        # Store raw data for verification (if needed)
        if data.get('include_raw', False):
            response['cose']['_raw'] = {
                'protected_bstr': base64.b64encode(cose['protected_bstr']).decode('ascii'),
                'payload_bstr': base64.b64encode(cose['payload_bstr']).decode('ascii'),
                'signature': base64.b64encode(cose['signature']).decode('ascii')
            }

        return jsonify(response)

    except Exception as e:
        logger.exception("Error decoding HCERT")
        return jsonify({'error': 'decode_error', 'details': str(e)}), 500

@app.route('/extract/metadata', methods=['POST'])
def extract_metadata():
    """Extract metadata (KID and issuer) from COSE/CWT."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'missing_data', 'details': 'JSON body required'}), 400
        
        cose = data.get('cose', {})
        payload = data.get('payload', {})
        
        # Handle JSON-safe bytes encoding
        if isinstance(cose.get('protected'), dict) and '_b64' in cose['protected']:
            # Decode from base64
            protected_b64 = cose['protected']['_b64']
            protected_bytes = base64.urlsafe_b64decode(protected_b64 + '=' * (4 - len(protected_b64) % 4))
            cose['protected'] = cbor2.loads(protected_bytes)
        
        kid_b64, kid_hex = extract_kid(cose)
        issuer = extract_issuer(payload)
        
        return jsonify({
            'kid': kid_b64 or kid_hex,
            'kid_b64': kid_b64,
            'kid_hex': kid_hex,
            'issuer': issuer
        })
        
    except Exception as e:
        logger.exception("Error extracting metadata")
        return jsonify({
            'error': 'extraction_error',
            'details': str(e)
        }), 500

@app.route('/extract/reference', methods=['POST'])
def extract_reference():
    """Extract SHLink/VHL reference from either HCERT (…[5]) or payload[-260][5]."""
    try:
        data = request.get_json() or {}
        hcert = data.get('hcert')
        payload = data.get('payload')

        def normalize_ref(ref):
            if isinstance(ref, list) and ref:
                first = ref[0]
                if isinstance(first, dict):
                    return first.get('u') or first.get('url')
                return first
            return ref

        if isinstance(hcert, dict):
            ref = hcert.get(5) or hcert.get('5')
            ref = normalize_ref(ref)
            if isinstance(ref, (str, bytes)):
                return jsonify(parse_shlink_reference({5: ref}))

        if isinstance(payload, dict):
            container = payload.get(-260) or payload.get('-260')
            if isinstance(container, dict):
                ref = container.get(5) or container.get('5')
                ref = normalize_ref(ref)
                if isinstance(ref, (str, bytes)):
                    return jsonify(parse_shlink_reference({5: ref}))

        return jsonify({'hasReference': False, 'error': 'no_reference_found'}), 404

    except Exception as e:
        logger.exception("Error extracting reference")
        return jsonify({'error': 'extraction_error', 'details': str(e)}), 500

@app.route('/shlink/authorize', methods=['POST'])
def shlink_authorize():
    """Authorize SHLink with PIN."""
    try:
        data = request.get_json()
        if not data or 'url' not in data or 'pin' not in data:
            return jsonify({'error': 'missing_fields', 'details': 'url and pin fields required'}), 400
        
        url = data['url']
        pin = data['pin']
        
        manifest = None
        
        # Try different PIN submission methods
        methods = [
            ('JSON POST', lambda: requests.post(url, json={'passcode': str(pin)}, headers={'Content-Type': 'application/json'}, allow_redirects=True, timeout=30)),
            ('Form POST', lambda: requests.post(url, data={'passcode': str(pin)}, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=30)),
            ('Query param', lambda: requests.get(f"{url}{'&' if '?' in url else '?'}passcode={pin}", allow_redirects=True, timeout=30))
        ]
        
        for method_name, method_func in methods:
            try:
                response = method_func()
                if response.status_code == 200:
                    try:
                        manifest = response.json()
                    except:
                        manifest = {'raw': response.text, 'content_type': response.headers.get('Content-Type', 'text/plain')}
                    break
            except Exception as e:
                logger.debug(f"{method_name} failed: {e}")
        
        if not manifest:
            return jsonify({
                'error': 'authorization_failed',
                'details': 'Could not authorize with provided PIN'
            }), 400
        
        if isinstance(manifest, dict) and 'raw' in manifest:
            return jsonify(manifest)
        else:
            return jsonify({'manifest': manifest})
        
    except Exception as e:
        logger.exception("Error authorizing SHLink")
        return jsonify({
            'error': 'authorization_error',
            'details': str(e)
        }), 500

@app.route('/shlink/fetch-fhir', methods=['POST'])
def shlink_fetch_fhir():
    """Fetch FHIR resources from SHLink manifest."""
    try:
        data = request.get_json(silent=True) or {}   # ← tolerate bad JSON
        if 'manifest' not in data:
            return jsonify({'error': 'missing_manifest', 'details': 'manifest field required'}), 400
        
        manifest = data['manifest']
        fhir_resources = []
        errors = []
        
        url_sources = []

        if isinstance(manifest.get('entries'), list):
            for entry in manifest['entries']:
                if isinstance(entry, dict) and isinstance(entry.get('url'), str):
                    url_sources.append(entry['url'])

        if isinstance(manifest.get('files'), list):
            for f in manifest['files']:
                if not isinstance(f, dict):
                    continue
                if isinstance(f.get('location'), str):
                    url_sources.append(f['location'])
                elif isinstance(f.get('url'), str):
                    url_sources.append(f['url'])

        if isinstance(manifest.get('links'), list):
            for link in manifest['links']:
                if isinstance(link, dict) and isinstance(link.get('href'), str):
                    url_sources.append(link['href'])
        
        direct_fhir = None
        for key in ['fhirBundle', 'healthCertificate', 'certificate', 'data']:
            if key in manifest:
                direct_fhir = manifest[key]
                break
        
        if direct_fhir:
            if isinstance(direct_fhir, dict) and ('resourceType' in direct_fhir or 'entry' in direct_fhir):
                fhir_resources.append({
                    'url': 'embedded',
                    'resource': direct_fhir
                })
        
        for url in url_sources:
            try:
                headers = {'Accept': 'application/fhir+json, application/json'}
                response = requests.get(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict) and ('resourceType' in data or 'entry' in data):
                            fhir_resources.append({
                                'url': url,
                                'resource': data
                            })
                        else:
                            fhir_resources.append({
                                'url': url,
                                'data': data
                            })
                    except:
                        fhir_resources.append({
                            'url': url,
                            'text_preview': response.text[:500]
                        })
                else:
                    errors.append(f"Failed to fetch {url}: HTTP {response.status_code}")
                    
            except Exception as e:
                errors.append(f"Error fetching {url}: {str(e)}")
        
        return jsonify({
            'found': len(fhir_resources) > 0,
            'fhir': fhir_resources,
            'errors': errors
        })
        
    except Exception as e:
        logger.exception("Error fetching FHIR")
        return jsonify({
            'error': 'fetch_error',
            'details': str(e)
        }), 500

# -------- New Signature Verification Endpoints --------

@app.route('/gdhcn/trustlist', methods=['GET', 'POST'])
def fetch_trustlist():
    """Fetch GDHCN trustlist DID document."""
    try:
        if request.method == 'POST':
            data = request.get_json() or {}
        else:
            data = request.args.to_dict()
        
        env = data.get('env', 'prod')
        domain = data.get('domain', 'DCC')
        participant = data.get('participant', '-')
        usage = data.get('usage', 'DSC')
        
        did = build_trustlist_did(env, domain, participant, usage)
        url = did_web_to_url(did)
        
        logger.info(f"Fetching trustlist: {url}")
        trust_doc = fetch_json(url)
        
        return jsonify({
            'did': did,
            'url': url,
            'document': trust_doc,
            'verification_methods_count': len(trust_doc.get('verificationMethod', []))
        })
        
    except Exception as e:
        logger.exception("Error fetching trustlist")
        return jsonify({
            'error': 'trustlist_fetch_failed',
            'details': str(e)
        }), 500

@app.route('/gdhcn/verify-trustlist', methods=['POST'])
def verify_trustlist_integrity():
    """Verify the JsonWebSignature2020 proof of a trustlist DID document."""
    try:
        data = request.get_json()
        if not data or 'document' not in data:
            return jsonify({'error': 'missing_document', 'details': 'document field required'}), 400
        
        trust_doc = data['document']
        context_dir = data.get('context_dir', 'contexts')
        allow_remote = data.get('allow_remote_contexts', False)
        
        # Setup JSON-LD context loader
        loader = make_local_context_loader(context_dir, allow_remote=allow_remote)
        jsonld.set_document_loader(loader)
        
        try:
            vm_id, alg = verify_jsonwebsignature2020(trust_doc, loader)
            
            return jsonify({
                'valid': True,
                'verification_method': vm_id,
                'algorithm': alg,
                'message': 'DID proof verified successfully'
            })
            
        except Exception as e:
            return jsonify({
                'valid': False,
                'error': str(e),
                'message': 'DID proof verification failed'
            }), 400
            
    except Exception as e:
        logger.exception("Error verifying trustlist")
        return jsonify({
            'error': 'verification_error',
            'details': str(e)
        }), 500

@app.route('/gdhcn/extract-keys', methods=['POST'])
def extract_keys_from_trustlist():
    """Extract public keys from a trustlist DID document."""
    try:
        data = request.get_json()
        if not data or 'document' not in data:
            return jsonify({'error': 'missing_document', 'details': 'document field required'}), 400
        
        trust_doc = data['document']
        keys_data = []
        
        for vm in trust_doc.get('verificationMethod', []):
            jwk_obj = vm.get('publicKeyJwk')
            if not jwk_obj:
                continue
            
            # Extract key info
            kid = jwk_obj.get('kid')
            x5c = jwk_obj.get('x5c')
            
            key_info = {
                'id': vm.get('id'),
                'kid': kid,
                'kty': jwk_obj.get('kty'),
                'crv': jwk_obj.get('crv'),
                'has_x5c': bool(x5c)
            }
            
            # Try to extract certificate info if x5c present
            if x5c:
                try:
                    leaf_der = base64.b64decode(x5c[0])
                    cert = x509.load_der_x509_certificate(leaf_der)
                    key_info['cert_subject'] = cert.subject.rfc4514_string()
                    key_info['cert_issuer'] = cert.issuer.rfc4514_string()
                    key_info['cert_not_after'] = cert.not_valid_after.isoformat()
                except Exception as e:
                    key_info['cert_error'] = str(e)
            
            keys_data.append(key_info)
        
        return jsonify({
            'count': len(keys_data),
            'keys': keys_data
        })
        
    except Exception as e:
        logger.exception("Error extracting keys")
        return jsonify({
            'error': 'extraction_error',
            'details': str(e)
        }), 500

@app.route('/verify/signature', methods=['POST'])
def verify_signature():
    """Verify COSE signature using provided keys or GDHCN trustlist."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'missing_data', 'details': 'JSON body required'}), 400
        
        # Get COSE data
        cose_raw = data.get('cose_raw')
        if not cose_raw:
            # Try to get from a decoded HCERT response
            cose = data.get('cose', {})
            if cose and '_raw' in cose:
                cose_raw = cose['_raw']
            else:
                return jsonify({'error': 'missing_cose_raw', 'details': 'cose_raw field required'}), 400
        
        # Decode raw COSE data
        if 'protected_bstr' in cose_raw and 'payload_bstr' in cose_raw and 'signature' in cose_raw:
            protected_bstr = base64.b64decode(cose_raw['protected_bstr'])
            payload_bstr = base64.b64decode(cose_raw['payload_bstr'])
            signature = base64.b64decode(cose_raw['signature'])
            logger.info(f"[verify] Raw signature length: {len(signature)} bytes")
            logger.info(f"[verify] Signature hex preview: {signature[:32].hex()}...")
        else:
            return jsonify({'error': 'invalid_cose_raw', 'details': 'cose_raw must contain protected_bstr, payload_bstr, and signature'}), 400
        
        # Get verification options
        use_gdhcn = data.get('use_gdhcn', False)
        gdhcn_env = data.get('gdhcn_env', 'prod')
        participant = data.get('participant', '-')
        domain = data.get('domain', 'DCC')
        usage = data.get('usage', 'DSC')
        verify_did_proof = data.get('verify_did_proof', True)
        allow_remote_contexts = data.get('allow_remote_contexts', False)
        context_dir = data.get('context_dir', 'contexts')
        
        # Parse protected headers to get KID and algorithm
        protected_headers = cbor2.loads(protected_bstr)
        alg = protected_headers.get(1)
        logger.info(f"[verify] Algorithm in header: {alg} (expected -7 for ES256)")
        
        kid_b64, kid_hex = extract_kid({'protected': protected_headers, 'unprotected': {}})
        logger.info(f"[verify] Looking for KID: b64={kid_b64}, hex={kid_hex}")
        protected_headers_json = bytes_to_json_safe(protected_headers)

        if alg != -7:
            return jsonify({
                'valid': False,
                'error': 'unsupported_algorithm',
                'details': f'Algorithm {alg} not supported, expected -7 (ES256)',
                'algorithm_found': alg,
                'protected_headers': protected_headers_json,   # optional but handy
            }), 400
        
        candidates = []
        trustlist_verified = False
        trustlist_keys_info = []
        trustlist_meta = None   # NEW: ensure defined even if GDHCN not used
        
        # Fetch keys from GDHCN if requested
        if use_gdhcn:
            try:
                # Fetch trustlist
                did = build_trustlist_did(gdhcn_env, domain, participant, usage)
                url = did_web_to_url(did)
                logger.info(f"[verify] Fetching trustlist from: {url}")
                trust_doc = fetch_json(url)
                trustlist_meta = {"did": did, "url": url} if use_gdhcn else None

                # Verify trustlist integrity if requested
                if verify_did_proof:
                    try:
                        loader = make_local_context_loader(context_dir, allow_remote=allow_remote_contexts)
                        jsonld.set_document_loader(loader)
                        vm_id, alg = verify_jsonwebsignature2020(trust_doc, loader)
                        trustlist_verified = True
                        logger.info(f"[verify] Trustlist DID proof verified: vm={vm_id}, alg={alg}")
                    except Exception as e:
                        logger.warning(f"[verify] Trustlist verification failed: {e}")
                        if not data.get('allow_unverified_trustlist', False):
                            return jsonify({
                                'valid': False,
                                'error': 'trustlist_verification_failed',
                                'details': str(e)
                            }), 400
                
                # Extract keys and log details
                keys = extract_pubkeys_from_trustlist_doc(trust_doc)
                logger.info(f"[verify] Extracted {len(keys)} keys from trustlist")
                
                for kid, pk in keys:
                    logger.info(f"[verify] Available key KID: {kid}")
                    trustlist_keys_info.append({'kid': kid, 'available': True})
                
                # Check if we have a matching KID
                if kid_b64:
                    matching_keys = [(k, pk) for (k, pk) in keys if k == kid_b64]
                    if matching_keys:
                        logger.info(f"[verify] Found {len(matching_keys)} matching key(s) for KID {kid_b64}")
                        candidates.extend(matching_keys)
                    else:
                        logger.warning(f"[verify] No matching key found for KID {kid_b64} in trustlist")
                    
                    # Add non-matching keys as fallback
                    non_matching = [(k, pk) for (k, pk) in keys if k != kid_b64]
                    candidates.extend(non_matching)
                else:
                    logger.info("[verify] No KID in header, trying all keys")
                    candidates.extend(keys)
                    
            except Exception as e:
                logger.error(f"[verify] GDHCN fetch failed: {e}", exc_info=True)
                if not data.get('fallback_on_error', True):
                    return jsonify({
                        'valid': False,
                        'error': 'gdhcn_fetch_failed',
                        'details': str(e)
                    }), 500
        
        # Try verification with candidates
        verification_attempts = []
        logger.info(f"[verify] Attempting verification with {len(candidates)} key(s)")
        
        for idx, (kid, pk) in enumerate(candidates, 1):
            logger.info(f"[verify] Attempt {idx}/{len(candidates)} with KID: {kid}")
            try:
                # This will either succeed or raise an exception
                verify_es256(pk, protected_bstr, payload_bstr, signature)
                
                # If we get here, verification succeeded
                logger.info(f"[verify] SUCCESS! Signature valid with KID: {kid}")
                return jsonify({
                    'valid': True,
                    'verified_with_kid': kid,
                    'trustlist_verified': trustlist_verified,
                    'gdhcn_env': gdhcn_env if use_gdhcn else None,
                    'trustlist': trustlist_meta,
                    'protected_headers': protected_headers_json,
                    'message': 'Signature valid'
                })
            except Exception as e:
                logger.warning(f"[verify] Verification failed with {kid}: {str(e)}")
                verification_attempts.append({
                    'kid': kid,
                    'error': str(e)
                })
        
        # All verification attempts failed
        logger.warning(f"[verify] All {len(candidates)} verification attempts failed")
        
        return jsonify({
            'valid': False,
            'kid_in_header': kid_b64,
            'kid_hex': kid_hex,
            'algorithm': alg,
            'candidates_tried': len(candidates),
            'trustlist_keys': trustlist_keys_info,
            'verification_attempts': verification_attempts,
            'trustlist': trustlist_meta,
            'protected_headers': protected_headers_json,            
            'message': 'Signature verification failed',
            'debug_info': {
                'gdhcn_env': gdhcn_env,
                'participant': participant,
                'domain': domain,
                'usage': usage,
                'signature_length': len(signature),
                'protected_length': len(protected_bstr),
                'payload_length': len(payload_bstr)
            }
        }), 400
        
    except Exception as e:
        logger.exception("[verify] Error verifying signature")
        return jsonify({
            'error': 'verification_error',
            'details': str(e)
        }), 500

# -------- Documentation and UI Endpoints --------

@app.route("/ui")
def serve_ui():
    """Serve the static HTML helper UI."""
    ui_path = os.path.join(os.path.dirname(__file__), "ui.html")
    if os.path.exists(ui_path):
        return send_from_directory(os.path.dirname(ui_path), "ui.html")
    return jsonify({"error": "ui_not_found", "details": "ui.html not present"}), 404

@app.route("/redocs")
def redoc():
    """Serve ReDoc documentation."""
    return """
    <!DOCTYPE html>
    <html>
      <head>
        <title>GDHCN Validator API Docs</title>
        <meta charset="utf-8"/>
        <link href="https://fonts.googleapis.com/css?family=Roboto:300,400,700" rel="stylesheet">
        <style>
          body { margin: 0; padding: 0; }
        </style>
      </head>
      <body>
        <redoc spec-url='/openapi.json'></redoc>
        <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
      </body>
    </html>
    """

# OpenAPI specification (complete)
OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "GDHCN HCERT & SHLink Validator API",
        "version": SERVICE_VERSION,
        "description": "Complete API for decoding EU DCC HC1 strings, verifying signatures via GDHCN trustlists, extracting metadata, and following SHLink references."
    },
    "servers": [{"url": "/"}],
    "paths": {
        "/status": {
            "get": {
                "summary": "Service status",
                "tags": ["Health"],
                "responses": {
                    "200": {
                        "description": "Service info",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Status"}
                            }
                        }
                    }
                }
            }
        },
        "/health": {
            "get": {
                "summary": "Health check",
                "tags": ["Health"],
                "responses": {
                    "200": {
                        "description": "Service health",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Status"}
                            }
                        }
                    }
                }
            }
        },
        "/decode/image": {
            "post": {
                "summary": "Decode QR from image",
                "tags": ["Decoding"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "type": "object",
                                "properties": {"image": {"type": "string", "format": "binary"}},
                                "required": ["image"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Decoded QR content",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DecodeImageResponse"}
                            }
                        }
                    },
                    "400": {
                        "description": "Decode failure",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    }
                }
            }
        },
        "/decode/hcert": {
            "post": {
                "summary": "Decode HC1 (HCERT) string",
                "tags": ["Decoding"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "qr_data": {"type": "string", "example": "HC1:..."},
                                    "include_raw": {"type": "boolean", "default": False, "description": "Include raw COSE data for verification"}
                                },
                                "required": ["qr_data"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Decoded COSE payload",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DecodeHcertResponse"}
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid HC1 / decode error",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    }
                }
            }
        },
        "/extract/metadata": {
            "post": {
                "summary": "Extract KID / issuer from COSE/CWT",
                "tags": ["Extraction"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "cose": {"type": "object"},
                                    "payload": {"type": "object"}
                                },
                                "required": ["cose", "payload"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Metadata",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/MetadataResponse"}
                            }
                        }
                    }
                }
            }
        },
        "/extract/reference": {
            "post": {
                "summary": "Extract SHLink reference",
                "tags": ["Extraction"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "hcert": {"type": "object", "nullable": True},
                                    "payload": {"type": "object", "nullable": True}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Reference details",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ReferenceResponse"}
                            }
                        }
                    },
                    "404": {
                        "description": "No reference found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    }
                }
            }
        },
        "/shlink/authorize": {
            "post": {
                "summary": "Authorize SHLink with PIN/passcode",
                "tags": ["SHLink"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "url": {"type": "string", "format": "uri"},
                                    "pin": {"type": "string"}
                                },
                                "required": ["url", "pin"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Manifest or raw response",
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"}
                            }
                        }
                    },
                    "400": {
                        "description": "Authorization failed",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    }
                }
            }
        },
        "/shlink/fetch-fhir": {
            "post": {
                "summary": "Fetch FHIR resources from manifest",
                "tags": ["SHLink"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"manifest": {"type": "object"}},
                                "required": ["manifest"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "FHIR results",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/FhirResponse"}
                            }
                        }
                    }
                }
            }
        },
        "/gdhcn/trustlist": {
            "get": {
                "summary": "Fetch GDHCN trustlist",
                "tags": ["GDHCN"],
                "parameters": [
                    {"name": "env", "in": "query", "schema": {"type": "string", "enum": ["prod", "uat", "dev"], "default": "prod"}},
                    {"name": "domain", "in": "query", "schema": {"type": "string", "default": "DCC"}},
                    {"name": "participant", "in": "query", "schema": {"type": "string", "default": "-"}},
                    {"name": "usage", "in": "query", "schema": {"type": "string", "default": "DSC"}}
                ],
                "responses": {
                    "200": {
                        "description": "Trustlist DID document",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TrustlistResponse"}
                            }
                        }
                    }
                }
            },
            "post": {
                "summary": "Fetch GDHCN trustlist",
                "tags": ["GDHCN"],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "env": {"type": "string", "enum": ["prod", "uat", "dev"], "default": "prod"},
                                    "domain": {"type": "string", "default": "DCC"},
                                    "participant": {"type": "string", "default": "-"},
                                    "usage": {"type": "string", "default": "DSC"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Trustlist DID document",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TrustlistResponse"}
                            }
                        }
                    }
                }
            }
        },
        "/gdhcn/verify-trustlist": {
            "post": {
                "summary": "Verify trustlist DID proof",
                "tags": ["GDHCN"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "document": {"type": "object"},
                                    "context_dir": {"type": "string", "default": "contexts"},
                                    "allow_remote_contexts": {"type": "boolean", "default": False}
                                },
                                "required": ["document"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Verification result",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/VerifyTrustlistResponse"}
                            }
                        }
                    },
                    "400": {
                        "description": "Verification failed",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/VerifyTrustlistResponse"}
                            }
                        }
                    }
                }
            }
        },
        "/gdhcn/extract-keys": {
            "post": {
                "summary": "Extract keys from trustlist",
                "tags": ["GDHCN"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "document": {"type": "object"}
                                },
                                "required": ["document"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Extracted keys",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ExtractKeysResponse"}
                            }
                        }
                    }
                }
            }
        },
        "/verify/signature": {
            "post": {
                "summary": "Verify COSE signature",
                "tags": ["Verification"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "cose_raw": {
                                        "type": "object",
                                        "properties": {
                                            "protected_bstr": {"type": "string", "description": "Base64 encoded protected headers"},
                                            "payload_bstr": {"type": "string", "description": "Base64 encoded payload"},
                                            "signature": {"type": "string", "description": "Base64 encoded signature"}
                                        }
                                    },
                                    "use_gdhcn": {"type": "boolean", "default": False, "description": "Use GDHCN trustlist for verification"},
                                    "gdhcn_env": {"type": "string", "enum": ["prod", "uat", "dev"], "default": "prod"},
                                    "participant": {"type": "string", "default": "-"},
                                    "domain": {"type": "string", "default": "DCC"},
                                    "usage": {"type": "string", "default": "DSC"},
                                    "verify_did_proof": {"type": "boolean", "default": True},
                                    "allow_remote_contexts": {"type": "boolean", "default": False},
                                    "allow_unverified_trustlist": {"type": "boolean", "default": False},
                                    "context_dir": {"type": "string", "default": "contexts"}
                                },
                                "required": ["cose_raw"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Signature valid",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/VerifySignatureResponse"}
                            }
                        }
                    },
                    "400": {
                        "description": "Signature invalid",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/VerifySignatureResponse"}
                            }
                        }
                    }
                }
            }
        }
    },
    "components": {
        "schemas": {
            "Status": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "version": {"type": "string"},
                    "ready": {"type": "boolean"},
                    "python": {"type": "string"},
                    "platform": {"type": "string"},
                    "libraries": {"type": "object", "additionalProperties": {"type": "string"}}
                }
            },
            "DecodeImageResponse": {
                "type": "object",
                "properties": {
                    "decoded": {"type": "boolean"},
                    "format": {"type": "string", "enum": ["hcert", "shlink", "url", "unknown"]},
                    "qr_data": {"type": "string"},
                    "normalization_note": {"type": "string"},
                    "removed_chars": {"type": "array", "items": {"type": "object"}}
                }
            },
            "DecodeHcertResponse": {
                "type": "object",
                "properties": {
                    "diagnostics": {
                        "type": "object",
                        "properties": {
                            "base45_decoded_len": {"type": "integer"},
                            "zlib_decompressed_len": {"type": "integer"}
                        }
                    },
                    "cose": {
                        "type": "object",
                        "properties": {
                            "protected": {"type": "object"},
                            "unprotected": {"type": "object"},
                            "kid_b64": {"type": "string", "nullable": True},
                            "kid_hex": {"type": "string", "nullable": True},
                            "signature": {"type": "string", "nullable": True},
                            "_raw": {
                                "type": "object",
                                "properties": {
                                    "protected_bstr": {"type": "string"},
                                    "payload_bstr": {"type": "string"},
                                    "signature": {"type": "string"}
                                }
                            }
                        }
                    },
                    "payload": {"type": "object"},
                    "hcert": {"type": "object", "nullable": True}
                }
            },
            "ReferenceResponse": {
                "type": "object",
                "properties": {
                    "hasReference": {"type": "boolean"},
                    "url": {"type": "string", "nullable": True},
                    "key": {"type": "string", "nullable": True},
                    "flags": {"type": "string", "nullable": True},
                    "exp": {"type": "integer", "nullable": True},
                    "raw": {"oneOf": [{"type": "string"}, {"type": "object"}], "nullable": True},
                    "error": {"type": "string", "nullable": True}
                }
            },
            "MetadataResponse": {
                "type": "object",
                "properties": {
                    "kid": {"type": "string", "nullable": True},
                    "kid_b64": {"type": "string", "nullable": True},
                    "kid_hex": {"type": "string", "nullable": True},
                    "issuer": {"type": "string", "nullable": True}
                }
            },
            "FhirResponse": {
                "type": "object",
                "properties": {
                    "found": {"type": "boolean"},
                    "fhir": {"type": "array", "items": {"type": "object"}},
                    "errors": {"type": "array", "items": {"type": "string"}}
                }
            },
            "TrustlistResponse": {
                "type": "object",
                "properties": {
                    "did": {"type": "string"},
                    "url": {"type": "string"},
                    "document": {"type": "object"},
                    "verification_methods_count": {"type": "integer"}
                }
            },
            "VerifyTrustlistResponse": {
                "type": "object",
                "properties": {
                    "valid": {"type": "boolean"},
                    "verification_method": {"type": "string"},
                    "algorithm": {"type": "string"},
                    "message": {"type": "string"},
                    "error": {"type": "string"}
                }
            },
            "ExtractKeysResponse": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer"},
                    "keys": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "kid": {"type": "string"},
                                "kty": {"type": "string"},
                                "crv": {"type": "string"},
                                "has_x5c": {"type": "boolean"},
                                "cert_subject": {"type": "string"},
                                "cert_issuer": {"type": "string"},
                                "cert_not_after": {"type": "string"}
                            }
                        }
                    }
                }
            },
            "VerifySignatureResponse": {
                "type": "object",
                "properties": {
                    "valid": {"type": "boolean"},
                    "verified_with_kid": {"type": "string", "nullable": True},
                    "trustlist_verified": {"type": "boolean"},
                    "gdhcn_env": {"type": "string", "nullable": True},
                    "message": {"type": "string"},
                    "kid_in_header": {"type": "string", "nullable": True},
                    "candidates_tried": {"type": "integer"},
                    "verification_attempts": {"type": "array", "items": {"type": "object"}}
                }
            },
            "Error": {
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "details": {"type": "string"}
                }
            }
        }
    },
    "tags": [
        {"name": "Health", "description": "Service health and status"},
        {"name": "Decoding", "description": "QR and HC1 decoding operations"},
        {"name": "Extraction", "description": "Data extraction operations"},
        {"name": "SHLink", "description": "SMART Health Link operations"},
        {"name": "GDHCN", "description": "GDHCN trustlist operations"},
        {"name": "Verification", "description": "Signature verification operations"}
    ]
}

@app.route("/openapi.json")
def openapi():
    """Serve OpenAPI specification."""
    spec = dict(OPENAPI_SPEC)
    spec["servers"] = [{"url": request.host_url.rstrip("/")}]
    return jsonify(spec)

@app.route("/docs")
def docs():
    """Serve Swagger UI documentation."""
    return f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>GDHCN Validator – API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
    <script>
      window.onload = () => {{
        window.ui = SwaggerUIBundle({{
          url: "{request.host_url.rstrip('/')}/openapi.json",
          dom_id: "#swagger-ui",
          presets: [SwaggerUIBundle.presets.apis],
          layout: "BaseLayout",
          docExpansion: "list",
          deepLinking: true
        }});
      }};
    </script>
  </body>
</html>
    """

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({'error': 'not_found', 'details': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    logger.exception("Internal server error")
    return jsonify({'error': 'internal_error', 'details': str(e)}), 500

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='GDHCN HCERT Validator Service')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()
    
    app.run(host=args.host, port=args.port, debug=args.debug)