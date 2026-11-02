#!/usr/bin/env python3
"""Construct and locally verify the researched TWDIW Android JWS profile."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


FIELDS = (
    "appHash", "appPlatform", "appVersion", "bodyHash", "keyId", "nonce", "timestamp"
)
HEADER = {"alg": "ES256", "typ": "JWT"}


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Expected unpadded Base64URL")
    data = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if _b64(data) != value:
        raise ValueError("Noncanonical Base64URL")
    return data


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member: " + key)
        result[key] = value
    return result


def _p256(key):
    if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        raise ValueError("Expected an EC key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("ES256 requires a P-256 key")


def public_text(key):
    """Canonical SPKI Base64 text, without PEM labels or whitespace."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = key.public_key()
    _p256(key)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode("ascii")


def key_id(key):
    return hashlib.sha256(public_text(key).encode("utf-8")).hexdigest()


def sign(body, key, *, app_id, app_version, nonce, timestamp_ms):
    """Sign exact body bytes with a caller-supplied application key."""
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("Signing requires a private EC key")
    _p256(key)
    for name, value in (("app_id", app_id), ("app_version", app_version), ("nonce", nonce)):
        if not isinstance(value, str) or not value:
            raise ValueError(name + " must be a nonempty string")
    if type(timestamp_ms) is not int or timestamp_ms <= 0:
        raise ValueError("timestamp_ms must be a positive integer in milliseconds")
    if not isinstance(body, bytes):
        raise ValueError("body must be bytes")
    payload = {
        "appHash": app_id,
        "appPlatform": "Android",
        "appVersion": app_version,
        "bodyHash": hashlib.sha256(body).hexdigest(),
        "keyId": key_id(key),
        "nonce": nonce,
        "timestamp": str(timestamp_ms),
    }
    signing_input = (_b64(_json(HEADER)) + "." + _b64(_json(payload))).encode("ascii")
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input.decode("ascii") + "." + _b64(raw)


def decode(jws):
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("Expected a compact JWS with three segments")
    header, payload = (
        json.loads(_unb64(part).decode("utf-8"), object_pairs_hook=_unique_object)
        for part in parts[:2]
    )
    raw = _unb64(parts[2])
    if not isinstance(header, dict) or header != HEADER:
        raise ValueError("Expected exactly alg=ES256 and typ=JWT, without header.kid")
    if not isinstance(payload, dict) or tuple(payload) != FIELDS:
        raise ValueError("Unexpected payload members or member order")
    if not all(isinstance(value, str) for value in payload.values()):
        raise ValueError("All seven payload members must be strings")
    if payload["appPlatform"] != "Android":
        raise ValueError("Unexpected Android profile platform")
    if not re.fullmatch(r"[0-9]+", payload["timestamp"]) or int(payload["timestamp"]) <= 0:
        raise ValueError("Invalid millisecond timestamp")
    if not payload["appHash"] or not payload["appVersion"] or not payload["nonce"]:
        raise ValueError("Application identity and nonce must be nonempty")
    for name in ("bodyHash", "keyId"):
        if not re.fullmatch(r"[0-9a-f]{64}", payload[name]):
            raise ValueError(name + " must be lowercase SHA-256 hex")
    if len(raw) != 64:
        raise ValueError("ES256 signature must be 64-byte R||S")
    return header, payload, raw, (parts[0] + "." + parts[1]).encode("ascii")


def verify(jws, key, *, body, nonce, app_id, app_version):
    """Verify signature plus caller-specified request and application context."""
    _p256(key)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = key.public_key()
    header, payload, raw, signing_input = decode(jws)
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    expected = {
        "appHash": app_id,
        "appVersion": app_version,
        "bodyHash": hashlib.sha256(body).hexdigest(),
        "keyId": key_id(key),
        "nonce": nonce,
    }
    for name, value in expected.items():
        if payload[name] != value:
            raise ValueError("Context mismatch: " + name)
    return {
        "signature_valid": True,
        "request_context_matches": True,
        "header": header,
        "payload": payload,
        "signature_bytes": len(raw),
        "server_acceptance_tested": False,
    }


def _write(path, data, *, private=False):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def demo(directory):
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    body = _json({"demo": True, "message": "TWDIW local signing test"})
    context = {
        "app_id": "diw.local.test",
        "app_version": "0.1.0-local",
        "nonce": "local-test-" + secrets.token_urlsafe(24),
        "timestamp_ms": time.time_ns() // 1_000_000,
    }
    jws = sign(body, key, **context)
    report = verify(jws, key.public_key(), body=body, **{
        name: context[name] for name in ("nonce", "app_id", "app_version")
    })
    report["nonce_source"] = "synthetic local test; not issued by the official server"
    report["signing_key_source"] = "new local test P-256 key"
    _, _, raw, signing_input = decode(jws)
    _write(directory / "test-private.pem", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), private=True)
    _write(directory / "public.pem", key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    _write(directory / "request-body.json", body)
    _write(directory / "signature.jws", (jws + "\n").encode("ascii"))
    _write(directory / "context.json", _json(context) + b"\n")
    _write(directory / "decoded.json", _json({"header": HEADER, "payload": report["payload"]}) + b"\n")
    _write(directory / "verification.json", json.dumps(report, indent=2).encode("utf-8") + b"\n")
    _write(directory / "signing-input.bin", signing_input)
    _write(directory / "signature.der", encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")))
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sample = sub.add_parser("demo", help="Generate a local test key, JWS and verification artifacts")
    sample.add_argument("--out", required=True, type=Path)
    for name in ("sign", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--body", required=True, type=Path)
        command.add_argument("--key", required=True, type=Path)
        command.add_argument("--app-id", required=True)
        command.add_argument("--app-version", required=True)
        command.add_argument("--nonce", required=True)
        if name == "sign":
            command.add_argument("--timestamp-ms", required=True, type=int)
        else:
            command.add_argument("--jws", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "demo":
            demo(args.out)
            return
        body, pem = args.body.read_bytes(), args.key.read_bytes()
        context = dict(app_id=args.app_id, app_version=args.app_version, nonce=args.nonce)
        if args.command == "sign":
            key = serialization.load_pem_private_key(pem, password=None)
            print(sign(body, key, **context, timestamp_ms=args.timestamp_ms))
        else:
            key = serialization.load_pem_public_key(pem)
            result = verify(args.jws.read_text("ascii").strip(), key, body=body, **context)
            print(json.dumps(result, indent=2))
    except (ValueError, InvalidSignature, OSError) as error:
        parser.exit(1, "Verification failed: invalid signature\n" if isinstance(error, InvalidSignature)
                    else "Error: " + str(error) + "\n")


if __name__ == "__main__":
    main()
