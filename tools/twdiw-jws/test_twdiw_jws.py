import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import twdiw_jws as subject


class TwdiwJwsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.body = b'{"z":2,"a":1}\n'
        cls.context = dict(app_id="diw.local.test", app_version="0.1.0-local", nonce="local-nonce")

    def sign(self):
        return subject.sign(self.body, self.key, **self.context, timestamp_ms=1793664000123)

    def test_wire_shape_and_public_text_fingerprint(self):
        token = self.sign()
        self.assertEqual(3, len(token.split(".")))
        self.assertNotIn("=", token)
        header_bytes = base64.urlsafe_b64decode(token.split(".")[0] + "==")
        self.assertEqual(b'{"alg":"ES256","typ":"JWT"}', header_bytes)
        _, payload, signature, _ = subject.decode(token)
        self.assertEqual(list(subject.FIELDS), list(payload))
        self.assertEqual("diw.local.test", payload["appHash"])
        self.assertEqual("Android", payload["appPlatform"])
        self.assertEqual("1793664000123", payload["timestamp"])
        der = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        expected = hashlib.sha256(base64.b64encode(der)).hexdigest()
        self.assertEqual(expected, payload["keyId"])
        self.assertNotEqual(hashlib.sha256(der).hexdigest(), payload["keyId"])
        self.assertEqual(hashlib.sha256(self.body).hexdigest(), payload["bodyHash"])
        self.assertEqual(64, len(signature))

    def test_wrong_context_and_wrong_key_are_rejected(self):
        token = self.sign()
        result = subject.verify(token, self.key.public_key(), body=self.body, **self.context)
        self.assertTrue(result["signature_valid"])
        with self.assertRaisesRegex(ValueError, "bodyHash"):
            subject.verify(token, self.key.public_key(), body=b'{"z":2,"a":1}', **self.context)
        changed = dict(self.context, nonce="another-nonce")
        with self.assertRaisesRegex(ValueError, "nonce"):
            subject.verify(token, self.key.public_key(), body=self.body, **changed)
        with self.assertRaises(InvalidSignature):
            subject.verify(token, ec.generate_private_key(ec.SECP256R1()).public_key(),
                           body=self.body, **self.context)

    def test_mutated_payload_and_signature_are_rejected(self):
        parts = self.sign().split(".")
        _, payload, signature, _ = subject.decode(".".join(parts))
        payload["appVersion"] = "changed"
        changed = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
        with self.assertRaises(InvalidSignature):
            subject.verify(parts[0] + "." + changed + "." + parts[2], self.key.public_key(),
                           body=self.body, **self.context)
        bad_signature = bytes([signature[0] ^ 1]) + signature[1:]
        parts[2] = base64.urlsafe_b64encode(bad_signature).rstrip(b"=").decode()
        with self.assertRaises(InvalidSignature):
            subject.verify(".".join(parts), self.key.public_key(), body=self.body, **self.context)

    def test_wrong_curve_and_header_kid_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "P-256"):
            subject.sign(self.body, ec.generate_private_key(ec.SECP384R1()),
                         **self.context, timestamp_ms=1793664000123)
        parts = self.sign().split(".")
        parts[0] = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT","kid":"extra"}').rstrip(b"=").decode()
        with self.assertRaisesRegex(ValueError, "header.kid"):
            subject.decode(".".join(parts))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL executable unavailable")
    def test_external_openssl_verifies_wire_signature(self):
        # Derive the signing input and DER signature directly from the token, independently of the tool's verifier.
        token = self.sign()
        h, p, signature = token.split(".")
        raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))

        def integer(data):
            data = data.lstrip(b"\x00") or b"\x00"
            if data[0] & 0x80:
                data = b"\x00" + data
            return b"\x02" + bytes([len(data)]) + data

        scalars = integer(raw[:32]) + integer(raw[32:])
        der = b"\x30" + bytes([len(scalars)]) + scalars
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "public.pem").write_bytes(self.key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            (root / "input.bin").write_bytes((h + "." + p).encode("ascii"))
            (root / "signature.der").write_bytes(der)
            result = subprocess.run([
                "openssl", "dgst", "-sha256", "-verify", str(root / "public.pem"),
                "-signature", str(root / "signature.der"), str(root / "input.bin"),
            ], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("Verified OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
