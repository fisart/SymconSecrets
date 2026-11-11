import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

spec = importlib.util.spec_from_file_location("witness", Path(__file__).parents[1] / "anchor/service.py")
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "anchor"
        self.public = w.Witness.initialize(self.directory)
        self.key = Ed25519PrivateKey.generate()
        self.info = {"deploymentId": str(uuid.uuid4()), "clientId": str(uuid.uuid4()), "keyId": w.b64(os.urandom(32)), "clientPublicKey": w.b64(self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)), "head": {"generation": w.b64(os.urandom(32)), "index": "0", "digest": "a" * 64, "commitId": str(uuid.uuid4())}}
        self.witness = w.Witness(self.directory)
        self.witness.provision(self.info, "b" * 64)

    def tearDown(self):
        self.temp.cleanup()

    def request(self, operation, body, certificate="b" * 64):
        request = {"version": "1", "deploymentId": self.info["deploymentId"], "clientId": self.info["clientId"], "keyId": self.info["keyId"], "requestId": str(uuid.uuid4()), "nonce": w.b64(os.urandom(32)), "operation": operation, "body": body}
        wire = {"request": request, "signature": w.b64(self.key.sign(b"SYMCON-ANCHOR-REQUEST-V1\0" + w.canonical(request)))}
        result = json.loads(self.witness.execute(w.canonical(wire), certificate))
        Ed25519PublicKey.from_public_bytes(w.binary(self.public["anchorPublicKey"], 32)).verify(w.binary(result["signature"], 64), b"SYMCON-ANCHOR-RESPONSE-V1\0" + w.canonical(result["response"]))
        self.assertEqual(result["response"]["nonce"], request["nonce"])
        return result["response"]

    def acquire(self):
        current = self.request("read", {})
        body = {"operationId": str(uuid.uuid4()), "expectedHead": current["head"], "expectedOwner": current["owner"], "newBootId": w.b64(os.urandom(32))}
        return self.request("acquire", body), body

    def test_restart_and_duplicate_acquire(self):
        first, body = self.acquire()
        self.witness = w.Witness(self.directory)
        second = self.request("acquire", body)
        self.assertEqual(first["owner"], second["owner"])
        self.assertEqual(second["owner"]["fence"], "1")

    def test_new_fence_rejects_old_authorization(self):
        old, _ = self.acquire()
        new, _ = self.acquire()
        body = {"operationId": str(uuid.uuid4()), "expectedHead": old["head"], "expectedOwner": old["owner"], "kind": "reveal", "actionDigest": "a" * 64, "audience": None}
        self.assertEqual(self.request("authorize", body)["result"]["status"], "REJECTED")
        self.assertEqual(new["owner"]["fence"], "2")

    def test_schema_credentials_and_unknown_deployment_fail(self):
        with self.assertRaises(PermissionError):
            self.request("read", {}, "c" * 64)
        with self.assertRaises(ValueError):
            self.request("read", {"unexpected": True})
        with self.assertRaises(ValueError):
            w.decode(b'{"duplicate":true,"duplicate":false}')
        with self.assertRaises(ValueError):
            w.number("9223372036854775808")

    def test_changed_retry_cannot_advance(self):
        current, _ = self.acquire()
        body = {"operationId": str(uuid.uuid4()), "expectedHead": current["head"], "expectedOwner": current["owner"], "target": dict(current["head"], index="1", digest="b" * 64, commitId=str(uuid.uuid4()))}
        applied = self.request("advance", body)
        body["target"]["digest"] = "c" * 64
        self.assertEqual(self.request("advance", body)["result"]["reason"], "ID_REUSE")
        self.assertEqual(self.request("read", {})["head"], applied["head"])


if __name__ == "__main__":
    unittest.main()
