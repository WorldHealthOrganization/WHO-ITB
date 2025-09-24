#!/usr/bin/env python3
"""
GDHCN HCERT & SMART Health Link Validator Service
Implements stepwise REST API for validating HCERT QR codes and following SHLink references.
"""

import base64
import io
import json
import logging
import platform
import re
import sys
import unicodedata
import zlib
from typing import Any, Dict, List, Optional, Tuple, Union
import os

import base45
import cbor2
import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from PIL import Image
from pyzbar import pyzbar



SERVICE_NAME = "HCERT & SHLink Validator"
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "1.0.0")


# -------- OpenAPI (Swagger) definition --------
OPENAPI_SPEC = {
  "openapi": "3.0.3",
  "info": {
    "title": "HCERT & SHLink Validator API",
    "version": SERVICE_VERSION,  # injected at runtime if you prefer
    "description": "Decode EU DCC HC1 strings (Base45 → zlib → CBOR → COSE), extract metadata, discover SHLink references, authorize with PIN/passcode, and fetch FHIR resources."
  },
  "servers": [{ "url": "/" }],
  "paths": {
    "/status": {
      "get": {
        "summary": "Service status",
        "responses": {
          "200": {
            "description": "Service info",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Status" },
                "examples": { "$ref": "#/components/examples/StatusOk" }
              }
            }
          }
        }
      }
    },
    "/health": {
      "get": {
        "summary": "Health check",
        "responses": {
          "200": {
            "description": "Service health",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Status" },
                "examples": { "$ref": "#/components/examples/StatusOk" }
              }
            }
          }
        }
      }
    },
    "/decode/image": {
      "post": {
        "summary": "Decode QR from image",
        "requestBody": {
          "required": True,
          "content": {
            "multipart/form-data": {
              "schema": {
                "type": "object",
                "properties": { "image": { "type": "string", "format": "binary" } },
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
                "schema": { "$ref": "#/components/schemas/DecodeImageResponse" },
                "examples": { "$ref": "#/components/examples/DecodeImageHcert" }
              }
            }
          },
          "400": {
            "description": "Decode failure",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" },
                "examples": { "$ref": "#/components/examples/ErrorNoQr" }
              }
            }
          }
        }
      }
    },
    "/decode/hcert": {
      "post": {
        "summary": "Decode HC1 (HCERT) string",
        "requestBody": {
          "required": True,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": { "qr_data": { "type": "string", "example": "HC1:..." } },
                "required": ["qr_data"]
              },
              "examples": { "$ref": "#/components/examples/DecodeHcertRequest" }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Decoded COSE payload",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/DecodeHcertResponse" },
                "examples": {
                  "PointerStyleWithSLink": { "$ref": "#/components/examples/DecodeHcertPointerResp" }
                }
              }
            }
          },
          "400": {
            "description": "Invalid HC1 / decode error",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" },
                "examples": { "$ref": "#/components/examples/ErrorInvalidBase45" }
              }
            }
          }
        }
      }
    },
    "/extract/metadata": {
      "post": {
        "summary": "Extract KID / issuer from COSE/CWT",
        "requestBody": {
          "required": True,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "cose": { "type": "object" },
                  "payload": { "type": "object" }
                },
                "required": ["cose", "payload"]
              },
              "examples": { "$ref": "#/components/examples/ExtractMetadataRequest" }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Metadata",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/MetadataResponse" },
                "examples": { "$ref": "#/components/examples/ExtractMetadataResponse" }
              }
            }
          },
          "400": {
            "description": "Bad request",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" }
              }
            }
          }
        }
      }
    },
    "/extract/reference": {
      "post": {
        "summary": "Extract SHLink reference (from hcert[5] or payload[-260][5])",
        "requestBody": {
          "required": True,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "hcert": { "type": "object", "nullable": True },
                  "payload": { "type": "object", "nullable": True }
                }
              },
              "examples": { "$ref": "#/components/examples/ExtractReferenceRequest" }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Reference details",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/ReferenceResponse" },
                "examples": { "$ref": "#/components/examples/ExtractReferenceResponse" }
              }
            }
          },
          "404": {
            "description": "No reference",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" },
                "examples": { "$ref": "#/components/examples/ErrorNoReference" }
              }
            }
          }
        }
      }
    },
    "/shlink/authorize": {
      "post": {
        "summary": "Authorize SHLink with PIN/passcode",
        "requestBody": {
          "required": True,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "url": { "type": "string", "format": "uri" },
                  "pin": { "type": "string" }
                },
                "required": ["url", "pin"]
              },
              "examples": { "$ref": "#/components/examples/AuthorizeRequest" }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Manifest or raw",
            "content": {
              "application/json": {
                "schema": { "type": "object" },
                "examples": { "$ref": "#/components/examples/AuthorizeResponse" }
              }
            }
          },
          "400": {
            "description": "Authorization failed",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" },
                "examples": { "$ref": "#/components/examples/ErrorAuthFailed" }
              }
            }
          }
        }
      }
    },
    "/shlink/fetch-fhir": {
      "post": {
        "summary": "Fetch FHIR resources from manifest",
        "requestBody": {
          "required": True,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": { "manifest": { "type": "object" } },
                "required": ["manifest"]
              },
              "examples": { "$ref": "#/components/examples/FetchFhirRequest" }
            }
          }
        },
        "responses": {
          "200": {
            "description": "FHIR results",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/FhirResponse" },
                "examples": { "$ref": "#/components/examples/FetchFhirResponse" }
              }
            }
          },
          "400": {
            "description": "Fetch error",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/Error" }
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
          "service": { "type": "string" },
          "version": { "type": "string" },
          "ready": { "type": "boolean" },
          "python": { "type": "string" },
          "platform": { "type": "string" },
          "libraries": { "type": "object", "additionalProperties": { "type": "string" } }
        }
      },
      "DecodeImageResponse": {
        "type": "object",
        "properties": {
          "decoded": { "type": "boolean" },
          "format": { "type": "string", "enum": ["hcert", "shlink", "url", "unknown"] },
          "qr_data": { "type": "string" },
          "normalization_note": { "type": "string" },
          "removed_chars": { "type": "array", "items": { "type": "object" } }
        }
      },
      "DecodeHcertResponse": {
        "type": "object",
        "properties": {
          "diagnostics": {
            "type": "object",
            "properties": {
              "base45_decoded_len": { "type": "integer" },
              "zlib_decompressed_len": { "type": "integer" }
            }
          },
          "cose": {
            "type": "object",
            "properties": {
              "protected": { "type": "object" },
              "unprotected": { "type": "object" },
              "kid_b64": { "type": "string", "nullable": True },
              "kid_hex": { "type": "string", "nullable": True },
              "signature": { "type": "string", "nullable": True }
            }
          },
          "payload": { "type": "object" },
          "hcert": { "type": "object", "nullable": True }
        }
      },
      "ReferenceResponse": {
        "type": "object",
        "properties": {
          "hasReference": { "type": "boolean" },
          "url": { "type": "string", "nullable": True },
          "key": { "type": "string", "nullable": True },
          "flags": { "type": "string", "nullable": True },
          "exp": { "type": "integer", "nullable": True },
          "raw": { "oneOf": [{ "type": "string" }, { "type": "object" }], "nullable": True },
          "error": { "type": "string", "nullable": True }
        }
      },
      "MetadataResponse": {
        "type": "object",
        "properties": {
          "kid": { "type": "string", "nullable": True },
          "kid_b64": { "type": "string", "nullable": True },
          "kid_hex": { "type": "string", "nullable": True },
          "issuer": { "type": "string", "nullable": True }
        }
      },
      "FhirResponse": {
        "type": "object",
        "properties": {
          "found": { "type": "boolean" },
          "fhir": { "type": "array", "items": { "type": "object" } },
          "errors": { "type": "array", "items": { "type": "string" } }
        }
      },
      "Error": {
        "type": "object",
        "properties": {
          "error": { "type": "string" },
          "details": { "type": "string" }
        }
      }
    },
    "examples": {
      "StatusOk": {
        "summary": "Healthy",
        "value": {
          "service": "HCERT & SHLink Validator",
          "version": "1.0.0",
          "ready": True,
          "python": "3.11.x",
          "platform": "Linux-...-x86_64-with-glibc2.31",
          "libraries": {
            "pillow": "10.2.0",
            "flask": "2.3.3",
            "cbor2": "5.6.4",
            "pyzbar": "0.1.9",
            "base45": "0.4.4"
          }
        }
      },
      "DecodeImageHcert": {
        "summary": "HC1 QR recognized",
        "value": {
          "decoded": True,
          "format": "hcert",
          "qr_data": "HC1:6BFOXNMG2N9HZBPYHQ3D69SO5D6%9L60JO DJS4L:P:R8LCDO%0AA3BI16TMVMJ3$C*2AL+J7AJENS:NK7VCECM:MQ0FE%JC5Y479D/*8G.CV3NV3OVLD86J:KE2HF86GX2BTLHA9A86GNY8XOIROBZQMQOB9MEBED:KE87B MH:8DZYK%KNU9O%UL75E2*KH42$T8CRJ.V89:GF-K8JVT$8LQN YVKY8$IV7/05T8::S%MV6J3$IV747ZIV7WN3$V8U8 IVNVG/U85VCEWVLTVUPVFCN.9FS0JE/8L-AXS8LMFLIF%57LSV$TFVZK%57NTV1IN1$VNVGHVVFWC9UVGYG8UVFGV%TFI3J5XK L0A/S3VGKJN5QN8$SAC71EN/6JU%8.YI3T8O8FPVNRT2OMNR3BBSNTGVCRNY83%%GEO0/933OJOLN4RVQJ0.H9PBL7EPYDK3I6.ROIAW231W/PUA16UEZ3IK6MABH53FW5909VRR91%MS*H9DMNCTNX7P0VYJH5 H7+SR/PTT89E7:TF3.EN$UF$B42SK72/QHR11U0VAY3C9JTB4MVVIB45TJ1XPU0U%*SBMRUS4*C5V.O+HEYBS930.80T5"
        }
      },
      "ErrorNoQr": {
        "summary": "No QR found",
        "value": { "error": "decode_failed", "details": "No QR code found in image", "decoded": False }
      },
      "DecodeHcertRequest": {
        "summary": "HC1 input",
        "value": {
          "qr_data": "HC1:6BFOXNMG2N9HZBPYHQ3D69SO5D6%9L60JO DJS4L:P:R8LCDO%0AA3BI16TMVMJ3$C*2AL+J7AJENS:NK7VCECM:MQ0FE%JC5Y479D/*8G.CV3NV3OVLD86J:KE2HF86GX2BTLHA9A86GNY8XOIROBZQMQOB9MEBED:KE87B MH:8DZYK%KNU9O%UL75E2*KH42$T8CRJ.V89:GF-K8JVT$8LQN YVKY8$IV7/05T8::S%MV6J3$IV747ZIV7WN3$V8U8 IVNVG/U85VCEWVLTVUPVFCN.9FS0JE/8L-AXS8LMFLIF%57LSV$TFVZK%57NTV1IN1$VNVGHVVFWC9UVGYG8UVFGV%TFI3J5XK L0A/S3VGKJN5QN8$SAC71EN/6JU%8.YI3T8O8FPVNRT2OMNR3BBSNTGVCRNY83%%GEO0/933OJOLN4RVQJ0.H9PBL7EPYDK3I6.ROIAW231W/PUA16UEZ3IK6MABH53FW5909VRR91%MS*H9DMNCTNX7P0VYJH5 H7+SR/PTT89E7:TF3.EN$UF$B42SK72/QHR11U0VAY3C9JTB4MVVIB45TJ1XPU0U%*SBMRUS4*C5V.O+HEYBS930.80T5"
        }
      },
      "DecodeHcertPointerResp": {
        "summary": "Pointer-style CWT with SHLink",
        "value": {
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
          "hcert": None
        }
      },
      "ErrorInvalidBase45": {
        "summary": "Invalid Base45",
        "value": { "error": "base45_decode_failed", "details": "invalid base45 string" }
      },
      "ExtractMetadataRequest": {
        "summary": "Use decode output",
        "value": {
          "cose": { "protected": { "1": -7, "4": "I1BAX8FATLs=" }, "unprotected": {} },
          "payload": { "1": "XJ", "4": 1745589915, "-260": { "5": [] } }
        }
      },
      "ExtractMetadataResponse": {
        "summary": "Issuer and KID",
        "value": { "kid": "I1BAX8FATLs=", "kid_b64": "I1BAX8FATLs=", "issuer": "XJ" }
      },
      "ExtractReferenceRequest": {
        "summary": "Pointer from payload",
        "value": {
          "hcert": None,
          "payload": {
            "-260": {
              "5": [
                {
                  "u": "shlink://eyJ1cmwiOiJodHRwOi8vbGFjcGFzcy5jcmVhdGUuY2w6ODE4Mi92Mi9tYW5pZmVzdHMvYmEwNzYxMWQtYjljOC00MTA0LWEwODYtNTU0ZDhiNmNjMDE0IiwiZmxhZyI6IlAiLCJleHAiOjE3NDU1ODk5MTU5NTMsImtleSI6InpURE9ETnRBTEktUXpuTXhKcGJqRFozeElLaEF2ZThQZ3I5VDFMODFMdVU9IiwibGFiZWwiOiJHREhDTiBWYWxpZGF0b3IifQ=="
                }
              ]
            }
          }
        }
      },
      "ExtractReferenceResponse": {
        "summary": "Resolved SHLink",
        "value": {
          "hasReference": True,
          "url": "http://lacpass.create.cl:8182/v2/manifests/ba07611d-b9c8-4104-a086-554d8b6cc014",
          "key": "zTDODNtALI-QznMxJpbjDZ3xIKhAve8Pgr9T1L81LuU=",
          "flags": "P",
          "exp": 1745589915953,
          "raw": {
            "url": "http://lacpass.create.cl:8182/v2/manifests/ba07611d-b9c8-4104-a086-554d8b6cc014",
            "key": "zTDODNtALI-QznMxJpbjDZ3xIKhAve8Pgr9T1L81LuU=",
            "flag": "P",
            "exp": 1745589915953,
            "label": "GDHCN Validator"
          }
        }
      },
      "ErrorNoReference": {
        "summary": "No SHLink found",
        "value": { "hasReference": False, "error": "no_reference_found" }
      },
      "AuthorizeRequest": {
        "summary": "Authorize with passcode",
        "value": {
          "url": "http://lacpass.create.cl:8182/v2/manifests/ba07611d-b9c8-4104-a086-554d8b6cc014",
          "pin": "1234"
        }
      },
      "AuthorizeResponse": {
        "summary": "Manifest example",
        "value": {
          "manifest": {
            "files": [
              {
                "contentType": "application/fhir+json",
                "location": "http://lacpass.create.cl:8182/v2/ips-json/ba07611d-b9c8-4104-a086-554d8b6cc014?key=b67e1488-b40b-4a79-b213-3dcad22cf1e4"
              }
            ]
          }
        }
      },
      "ErrorAuthFailed": {
        "summary": "Bad PIN",
        "value": { "error": "authorization_failed", "details": "Could not authorize with provided PIN" }
      },
      "FetchFhirRequest": {
        "summary": "Manifest with files[].location",
        "value": {
          "manifest": {
            "files": [
              {
                "contentType": "application/fhir+json",
                "location": "http://lacpass.create.cl:8182/v2/ips-json/ba07611d-b9c8-4104-a086-554d8b6cc014?key=b67e1488-b40b-4a79-b213-3dcad22cf1e4"
              }
            ]
          }
        }
      },
      "FetchFhirResponse": {
        "summary": "FHIR bundle fetched",
        "value": {
          "found": True,
          "fhir": [
            {
              "url": "http://lacpass.create.cl:8182/v2/ips-json/ba07611d-b9c8-4104-a086-554d8b6cc014?key=b67e1488-b40b-4a79-b213-3dcad22cf1e4",
              "resource": { "resourceType": "Bundle", "type": "collection", "entry": [ { "resource": { "resourceType": "Patient" } } ] }
            }
          ],
          "errors": []
        }
      }
    }
  }
}






# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Version info
SERVICE_NAME = "HCERT & SHLink Validator"
SERVICE_VERSION = "1.0.0"

# Base45 alphabet
BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


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
    
    return versions


def normalize_text(text: str) -> Tuple[str, List[Dict]]:
    """
    Normalize text for processing:
    - Unicode NFKC normalization
    - Strip all whitespace
    - Remove hidden characters
    Returns normalized text and list of removed characters.
    """
    # Unicode NFKC normalization
    text = unicodedata.normalize('NFKC', text)
    
    removed_chars = []
    
    # Track and remove various whitespace and hidden characters
    hidden_chars = [
        '\u00A0',  # Non-breaking space
        '\u200B',  # Zero-width space
        '\u200C',  # Zero-width non-joiner
        '\u200D',  # Zero-width joiner
        '\uFEFF',  # Zero-width no-break space
        '\u2060',  # Word joiner
    ]
    
    for char in hidden_chars:
        if char in text:
            removed_chars.append({
                'char': f'U+{ord(char):04X}',
                'name': unicodedata.name(char, 'UNKNOWN')
            })
            text = text.replace(char, '')
    
    # Remove all whitespace
    text_clean = re.sub(r'[\r\n\t]+', '', text)
    
    return text_clean, removed_chars


def sanitize_base45(text: str) -> Tuple[str, List[Dict]]:
    """
    Sanitize Base45 input by removing invalid characters.
    Returns sanitized text and list of invalid characters found.
    """
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
    """
    Recursively unwrap CBOR tags until we get to the actual data.
    Tag 18 = COSE_Sign1
    """
    while isinstance(data, cbor2.CBORTag):
        logger.info(f"Unwrapping CBOR Tag {data.tag}")
        data = data.value
    return data


def decode_cose_sign1(data: bytes) -> Dict[str, Any]:
    """
    Decode COSE_Sign1 structure.
    Returns dict with protected, unprotected, payload, and signature.
    """
    # Decode CBOR
    cbor_data = cbor2.loads(data)
    
    # Unwrap CBOR tags (especially Tag 18)
    cbor_data = unwrap_cbor_tags(cbor_data)
    
    # COSE_Sign1 should be a 4-element list
    if not isinstance(cbor_data, list) or len(cbor_data) != 4:
        raise ValueError(f"Invalid COSE_Sign1 structure: expected 4-element list, got {type(cbor_data)} with {len(cbor_data) if isinstance(cbor_data, list) else 'N/A'} elements")
    
    protected_bstr, unprotected_map, payload_bstr, signature_bstr = cbor_data
    
    # Decode protected headers
    protected_headers = {}
    if protected_bstr:
        protected_headers = cbor2.loads(protected_bstr)
    
    # Decode payload
    payload = {}
    if payload_bstr:
        payload = cbor2.loads(payload_bstr)
    
    return {
        'protected': protected_headers,
        'unprotected': unprotected_map or {},
        'payload': payload,
        'signature': base64.urlsafe_b64encode(signature_bstr).decode('ascii').rstrip('=') if signature_bstr else None
    }


def extract_kid(cose_headers: Dict[str, Any]) -> Optional[str]:
    def find_kid(hdrs: Dict[str, Any]) -> Optional[Any]:
        return hdrs.get(4) or hdrs.get('4') if isinstance(hdrs, dict) else None

    kid = find_kid(cose_headers.get('protected', {})) or find_kid(cose_headers.get('unprotected', {}))
    if isinstance(kid, bytes):
        return base64.urlsafe_b64encode(kid).decode('ascii').rstrip('=')
    if isinstance(kid, dict) and '_b64' in kid:
        return kid['_b64']
    if isinstance(kid, str):
        return kid
    return None

def extract_issuer(payload: Dict[str, Any]) -> Optional[str]:
    issuer = payload.get('iss') or payload.get(1) or payload.get('1')
    return issuer if isinstance(issuer, str) else None


def parse_shlink_reference(hcert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse SHLink/VHL reference from HCERT entry 5.
    Supports: shlink://, base64url(url), plain URL
    """
    # Check for entry 5 (int or string key)
    ref = hcert.get(5) or hcert.get('5')
    
    if not ref:
        return {'hasReference': False}
    
    result = {'hasReference': True, 'raw': ref}
    
    # Convert to string if needed
    if isinstance(ref, bytes):
        ref = ref.decode('utf-8')
    
    if not isinstance(ref, str):
        return {'hasReference': False}
    
    # Check if it's a shlink://
    if ref.startswith('shlink://'):
        # Extract base64url JSON payload
        payload_b64 = ref[9:]  # Remove 'shlink://'
        try:
            # Decode base64url
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
    
    # Check if it's base64url encoded URL
    elif not ref.startswith('http'):
        try:
            # Try to decode as base64url
            decoded = base64.urlsafe_b64decode(ref + '=' * (4 - len(ref) % 4))
            decoded_str = decoded.decode('utf-8')
            if decoded_str.startswith('http'):
                result['url'] = decoded_str
        except:
            # Not base64url, treat as plain URL
            result['url'] = ref
    
    # Plain URL
    else:
        result['url'] = ref
    
    return result


def bytes_to_json_safe(obj: Any) -> Any:
    """Convert bytes to base64url for JSON serialization."""
    if isinstance(obj, bytes):
        return {'_b64': base64.urlsafe_b64encode(obj).decode('ascii').rstrip('=')}
    elif isinstance(obj, dict):
        return {k: bytes_to_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [bytes_to_json_safe(item) for item in obj]
    return obj


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
        # Check for image in request
        if 'image' not in request.files:
            return jsonify({'error': 'no_image', 'details': 'No image file provided'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'no_filename', 'details': 'No file selected'}), 400
        
        # Read and decode image
        image = Image.open(io.BytesIO(file.read()))
        
        # Convert to grayscale if needed
        if image.mode != 'L':
            image = image.convert('L')
        
        # Decode QR codes
        decoded_objects = pyzbar.decode(image)
        
        if not decoded_objects:
            return jsonify({
                'decoded': False,
                'errors': ['No QR code found in image']
            })
        
        # Get the first QR code
        qr = decoded_objects[0]
        raw_bytes = qr.data
        if raw_bytes.startswith(b'HC1:') or raw_bytes.startswith(b'shlink://') or raw_bytes.startswith(b'http'):
            qr_data = raw_bytes.decode('utf-8')
        else:
            qr_data = raw_bytes.hex()  # or base64 if you prefer
            
        # Normalize the data
        normalized_data, removed_chars = normalize_text(qr_data)
        
        # Determine format
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
    """Decode HCERT data from HC1: format and return JSON-safe structures."""
    try:
        data = request.get_json()
        if not data or 'qr_data' not in data:
            return jsonify({'error': 'missing_qr_data', 'details': 'qr_data field required'}), 400

        qr_data = data['qr_data']
        logger.info(f"[hcert] Raw input length={len(qr_data)}")


        # 1) Normalize
        qr_data, norm_chars = normalize_text(qr_data)
        if qr_data.startswith('<!DOCTYPE html') or qr_data.startswith('<html'):
            return jsonify({
                'error': 'html_received_instead_of_hc1',
                'details': 'Server received HTML, not an HC1 string. Check API_BASE/port or proxy.',
                'hint': 'Ensure the frontend is posting to your Flask API, not a static web server.'
            }), 400
        # logger.info(f"[hcert] After normalization length={len(qr_data)}; removed_hidden={len(norm_chars)}")

        # 2) Require HC1: prefix
        if not qr_data.startswith('HC1:'):
            return jsonify({
                'error': 'invalid_format',
                'details': 'Data must start with HC1:',
                'received_prefix': qr_data[:10] if len(qr_data) > 10 else qr_data
            }), 400

        # 3) Strip prefix
        hc1_data = qr_data[4:]
        logger.info(f"[hcert] HC1 payload length={len(hc1_data)}")

        # 4) Sanitize Base45 (logs any invalid chars)
        sanitized_data, invalid_chars = sanitize_base45(hc1_data)
#        sanitized_data = hc1_data # Assume well-formed for now


        # 5) Base45 decode -> zlib-compressed bytes
        try:
            compressed_data = base45.b45decode(sanitized_data)
            logger.info(f"[hcert] Base45 decoded bytes={len(compressed_data)} preview={compressed_data[:20]!r}")
        except Exception as e:
            logger.warning(f"[hcert] Base45 decode failed: {e}")
            return jsonify({
                'error': 'base45_decode_failed',
                'details': str(e)
                # 'invalid_chars_detected': invalid_chars
            }), 400

        # 6) zlib decompress -> COSE (CBOR)
        try:
            cbor_data = zlib.decompress(compressed_data)
            logger.info(f"[hcert] zlib decompressed bytes={len(cbor_data)} preview={cbor_data[:20]!r}")
        except Exception as e:
            logger.warning(f"[hcert] zlib decompress failed: {e}")
            return jsonify({'error': 'zlib_decompress_failed', 'details': str(e)}), 400

        # 7) COSE_Sign1 decode (CBOR -> [protected, unprotected, payload, signature])
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

        # 8) Extract HCERT from payload: payload[-260][1]
        payload = cose.get('payload', {}) or {}
        hcert = None
        if -260 in payload:
            container = payload[-260]
            if isinstance(container, dict) and 1 in container:
                hcert = container[1]
                logger.info("[hcert] Extracted HCERT (-260/1)")

        # 9) Extract KID (label 4) for convenience
        kid_b64 = extract_kid({'protected': cose['protected'], 'unprotected': cose['unprotected']})
        if kid_b64:
            logger.info(f"[hcert] KID (b64url)={kid_b64}")

        # 10) Build JSON-safe response (bytes -> base64url envelopes)
        response = {
            'diagnostics': {
                # 'removed_hidden_chars': len(norm_chars),
                # 'invalid_base45_chars': len(invalid_chars),
                'base45_decoded_len': len(compressed_data),
                'zlib_decompressed_len': len(cbor_data),
            },
            'cose': {
                'protected': bytes_to_json_safe(cose['protected']),
                'unprotected': bytes_to_json_safe(cose['unprotected']),
                'kid_b64': kid_b64,
                'signature': cose.get('signature'),  # already b64url in decode_cose_sign1
            },
            'payload': bytes_to_json_safe(payload),
            'hcert': bytes_to_json_safe(hcert) if hcert is not None else None
        }

        # if invalid_chars:
        #     response['note'] = f"Sanitized {len(invalid_chars)} invalid Base45 characters"

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
        
        # Extract KID
        kid = extract_kid(cose)
        
        # Extract issuer
        issuer = extract_issuer(payload)
        
        return jsonify({
            'kid': kid,
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

        # Helper: normalize various shapes into a raw reference string if present
        def normalize_ref(ref):
            # If it's a list of dicts like [{'u': 'shlink://...'}], pick first 'u'/'url'
            if isinstance(ref, list) and ref:
                first = ref[0]
                if isinstance(first, dict):
                    return first.get('u') or first.get('url')
                return first
            return ref

        # 1) Prefer hcert[5]
        if isinstance(hcert, dict):
            ref = hcert.get(5) or hcert.get('5')
            ref = normalize_ref(ref)
            if isinstance(ref, (str, bytes)):
                return jsonify(parse_shlink_reference({5: ref}))

        # 2) Fallback: payload[-260][5] (accept int and string keys)
        if isinstance(payload, dict):
            container = payload.get(-260) or payload.get('-260')
            if isinstance(container, dict):
                ref = container.get(5) or container.get('5')
                ref = normalize_ref(ref)
                if isinstance(ref, (str, bytes)):
                    return jsonify(parse_shlink_reference({5: ref}))

        # Nothing found
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
        
        # Try different PIN submission methods
        manifest = None
        
        # Method 1: JSON POST
        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post(url, json={'passcode': str(pin)}, headers=headers, allow_redirects=True, timeout=30)
            if response.status_code == 200:
                try:
                    manifest = response.json()
                except:
                    manifest = {'raw': response.text, 'content_type': response.headers.get('Content-Type', 'text/plain')}
        except Exception as e:
            logger.debug(f"JSON POST failed: {e}")
        
        # Method 2: Form POST
        if not manifest:
            try:
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                response = requests.post(url, data={'passcode': str(pin)}, headers=headers, allow_redirects=True, timeout=30)
                if response.status_code == 200:
                    try:
                        manifest = response.json()
                    except:
                        manifest = {'raw': response.text, 'content_type': response.headers.get('Content-Type', 'text/plain')}
            except Exception as e:
                logger.debug(f"Form POST failed: {e}")
        
        # Method 3: Query parameter
        if not manifest:
            try:
                query_url = f"{url}{'&' if '?' in url else '?'}passcode={pin}"
                response = requests.get(query_url, allow_redirects=True, timeout=30)
                if response.status_code == 200:
                    try:
                        manifest = response.json()
                    except:
                        manifest = {'raw': response.text, 'content_type': response.headers.get('Content-Type', 'text/plain')}
            except Exception as e:
                logger.debug(f"Query param failed: {e}")
        
        if not manifest:
            return jsonify({
                'error': 'authorization_failed',
                'details': 'Could not authorize with provided PIN'
            }), 400
        
        # Return manifest or raw response
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
        data = request.get_json()
        if not data or 'manifest' not in data:
            return jsonify({'error': 'missing_manifest', 'details': 'manifest field required'}), 400
        
        manifest = data['manifest']
        fhir_resources = []
        errors = []
        
        # Common patterns for finding URLs in manifests
        # Collect URLs from several common shapes
        url_sources = []

        # entries[].url
        if isinstance(manifest.get('entries'), list):
            for entry in manifest['entries']:
                if isinstance(entry, dict) and isinstance(entry.get('url'), str):
                    url_sources.append(entry['url'])

        # files[].(location|url)
        if isinstance(manifest.get('files'), list):
            for f in manifest['files']:
                if not isinstance(f, dict):
                    continue
                if isinstance(f.get('location'), str):
                    url_sources.append(f['location'])
                elif isinstance(f.get('url'), str):
                    url_sources.append(f['url'])

        # links[].href
        if isinstance(manifest.get('links'), list):
            for link in manifest['links']:
                if isinstance(link, dict) and isinstance(link.get('href'), str):
                    url_sources.append(link['href'])

        
        # Pattern 4: Direct FHIR bundle/certificate
        direct_fhir = None
        for key in ['fhirBundle', 'healthCertificate', 'certificate', 'data']:
            if key in manifest:
                direct_fhir = manifest[key]
                break
        
        if direct_fhir:
            # Check if it looks like FHIR
            if isinstance(direct_fhir, dict) and ('resourceType' in direct_fhir or 'entry' in direct_fhir):
                fhir_resources.append({
                    'url': 'embedded',
                    'resource': direct_fhir
                })
        
        # Fetch each URL
        for url in url_sources:
            try:
                headers = {'Accept': 'application/fhir+json, application/json'}
                response = requests.get(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Check if it looks like FHIR
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
                        # Not JSON, save text preview
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


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({'error': 'not_found', 'details': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    logger.exception("Internal server error")
    return jsonify({'error': 'internal_error', 'details': str(e)}), 500


@app.route("/openapi.json")
def openapi():
    # Optionally update server URL dynamically
    spec = dict(OPENAPI_SPEC)
    spec["servers"] = [{"url": request.host_url.rstrip("/")}]
    return jsonify(spec)


@app.route("/redocs")
def redoc():
    return """
    <!DOCTYPE html>
    <html>
      <head>
        <title>HCERT & SHLink Validator API Docs</title>
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


@app.route("/docs")
def docs():
    # Minimal Swagger UI (uses public CDN for assets)
    return f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>HCERT & SHLink Validator – API Docs</title>
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



@app.route("/ui")
def serve_ui():
    """Serve the static HTML helper UI."""
    ui_path = os.path.join(os.path.dirname(__file__), "ui.html")
    if os.path.exists(ui_path):
        return send_from_directory(os.path.dirname(ui_path), "ui.html")
    return jsonify({"error": "ui_not_found", "details": "ui.html not present"}), 404



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)