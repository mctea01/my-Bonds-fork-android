import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().with_name("GenerateApplicationKey.java")
PRIVATE = "DIW_TWDIW_APP_PRIVATE_KEY"
PUBLIC = "DIW_TWDIW_APP_PUBLIC_KEY"


class ApplicationKeyBuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        subprocess.run(["javac", "-d", str(cls.root), str(SOURCE)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.working = tempfile.TemporaryDirectory()
        self.addCleanup(self.working.cleanup)
        self.path = Path(self.working.name)

    def invoke(self, path, values=None):
        env = dict(os.environ)
        env.pop(PRIVATE, None)
        env.pop(PUBLIC, None)
        env.update(values or {})
        return subprocess.run(["java", "-cp", str(self.root), "GenerateApplicationKey", str(path / "source"), str(path / "state")],
                              capture_output=True, text=True, env=env)

    def pair(self, path):
        result = self.invoke(path)
        self.assertEqual(0, result.returncode, result.stderr)
        values = {}
        for line in (path / "state/generated-key.properties").read_text().splitlines():
            if line and not line.startswith("#"):
                name, value = line.split("=", 1)
                values[name] = value.replace("\\=", "=")
        return values

    def test_blank_values_generate_a_pair_reused_by_apk_and_aab(self):
        first = self.invoke(self.path, {PRIVATE: "  ", PUBLIC: ""})
        self.assertEqual(0, first.returncode, first.stderr)
        source = self.path / "source/diw/wallet/app/BuiltInTwdiwApplicationKey.kt"
        before = source.read_bytes()
        modified = source.stat().st_mtime_ns
        second = self.invoke(self.path)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(before, source.read_bytes())
        self.assertEqual(modified, source.stat().st_mtime_ns)
        self.assertIn('source = "generated"', before.decode())
        if os.name != "nt":
            self.assertEqual(0o600, source.stat().st_mode & 0o777)
            self.assertEqual(0o600, (self.path / "state/generated-key.properties").stat().st_mode & 0o777)

    def test_supplied_base64_pair_is_validated_and_imported(self):
        pair = self.pair(self.path / "origin")
        target = self.path / "provided"
        result = self.invoke(target, {PRIVATE: pair["private"], PUBLIC: pair["public"]})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('source = "provided"', (target / "source/diw/wallet/app/BuiltInTwdiwApplicationKey.kt").read_text())
        self.assertFalse((target / "state/generated-key.properties").exists())
        self.assertNotIn(pair["private"], result.stdout + result.stderr)

    def test_pem_input_accepts_newlines(self):
        pair = self.pair(self.path / "origin")
        values = {PRIVATE: "-----BEGIN PRIVATE KEY-----\n" + pair["private"] + "\n-----END PRIVATE KEY-----",
                  PUBLIC: "-----BEGIN PUBLIC KEY-----\n" + pair["public"] + "\n-----END PUBLIC KEY-----"}
        result = self.invoke(self.path / "provided", values)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_partial_secret_does_not_silently_generate_a_replacement(self):
        secret = "LOCAL_TEST_SECRET_MUST_NOT_BE_LOGGED"
        result = self.invoke(self.path, {PRIVATE: secret})
        self.assertNotEqual(0, result.returncode)
        self.assertIn("must be supplied together", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertFalse((self.path / "state/generated-key.properties").exists())

    def test_mismatched_pair_is_rejected(self):
        first = self.pair(self.path / "first")
        second = self.pair(self.path / "second")
        result = self.invoke(self.path / "mismatch", {PRIVATE: first["private"], PUBLIC: second["public"]})
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn(first["private"], result.stdout + result.stderr)
        self.assertFalse((self.path / "mismatch/source/diw/wallet/app/BuiltInTwdiwApplicationKey.kt").exists())

    def test_invalid_keys_do_not_appear_in_errors(self):
        secret = "INVALID_PRIVATE_MATERIAL_123456"
        result = self.invoke(self.path, {PRIVATE: secret, PUBLIC: "invalid-public"})
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_corrupt_local_state_fails_without_regenerating(self):
        self.pair(self.path)
        source = self.path / "source/diw/wallet/app/BuiltInTwdiwApplicationKey.kt"
        before = source.read_bytes()
        (self.path / "state/generated-key.properties").write_text("private=corrupt\npublic=corrupt\n")
        result = self.invoke(self.path)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(before, source.read_bytes())

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL unavailable")
    def test_wrong_curve_is_rejected(self):
        private = subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"], capture_output=True, check=True).stdout
        public = subprocess.run(["openssl", "pkey", "-pubout"], input=private, capture_output=True, check=True).stdout
        result = self.invoke(self.path, {PRIVATE: private.decode(), PUBLIC: public.decode()})
        self.assertNotEqual(0, result.returncode)
        self.assertIn("P-256", result.stderr)


if __name__ == "__main__":
    unittest.main()
