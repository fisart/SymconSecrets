#!/usr/bin/env python3
"""Independent witness for the development vault. Run outside every Symcon restore domain.

HTTPS with mandatory client certificates; Ed25519 messages; a durable SQLite decision ledger.
No vault values or vault keys are accepted. Host provisioning is a separate command.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

QMAX = 9223372036854775807


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def binary(text, size):
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise ValueError("binary encoding")
    value = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if len(value) != size or b64(value) != text:
        raise ValueError("binary size")
    return value


def canonical(value):
    def check(node):
        if node is None or isinstance(node, bool):
            return
        if isinstance(node, str) and all(32 <= ord(c) <= 126 for c in node):
            return
        if isinstance(node, list):
            for item in node:
                check(item)
            return
        if isinstance(node, dict):
            for key, item in node.items():
                check(key)
                check(item)
            return
        raise ValueError("closed ASCII JCS profile: integers are decimal strings")
    check(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    if len(raw) > 65536:
        raise ValueError("body too large")
    result = json.loads(raw, object_pairs_hook=unique)
    canonical(result)
    return result


def fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError("closed schema")


def uuid(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value):
        raise ValueError("UUIDv4")


def number(value):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value) or int(value) > QMAX:
        raise ValueError("exact decimal")


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("digest")


def head(value):
    fields(value, ["generation", "index", "digest", "commitId"])
    binary(value["generation"], 32)
    number(value["index"])
    digest(value["digest"])
    uuid(value["commitId"])


def owner(value):
    fields(value, ["fence", "bootId", "clientId"])
    number(value["fence"])
    binary(value["bootId"], 32)
    uuid(value["clientId"])


class Witness:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.key = Ed25519PrivateKey.from_private_bytes((self.directory / "sign.key").read_bytes())
        self.key_id = (self.directory / "key-id").read_text().strip()

    def connect(self):
        db = sqlite3.connect(self.directory / "anchor.sqlite", timeout=2)
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def initialize(directory):
        path = Path(directory)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.stat().st_mode & 0o077 or path.is_symlink():
            raise ValueError("private non-symlinked witness directory required")
        key = Ed25519PrivateKey.generate()
        for name, data in [("sign.key", key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())), ("key-id", b64(os.urandom(32)).encode())]:
            with open(path / name, "xb") as stream:
                os.chmod(path / name, 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        db = sqlite3.connect(path / "anchor.sqlite")
        os.chmod(path / "anchor.sqlite", 0o600)
        db.executescript("CREATE TABLE deployments(id TEXT PRIMARY KEY, head TEXT NOT NULL, owner TEXT NOT NULL, credential_revision TEXT NOT NULL, clients TEXT NOT NULL); CREATE TABLE decisions(deployment TEXT NOT NULL, operation_id TEXT NOT NULL, digest TEXT NOT NULL, client TEXT NOT NULL, audience TEXT, decision TEXT NOT NULL, PRIMARY KEY(deployment,operation_id));")
        db.commit()
        db.close()
        sync_directory(path)
        sync_directory(path.parent)
        return {"anchorPublicKey": b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)), "anchorKeyId": (path / "key-id").read_text()}

    def provision(self, info, certificate_sha256):
        uuid(info["deploymentId"])
        uuid(info["clientId"])
        head(info["head"])
        binary(info["clientPublicKey"], 32)
        binary(info["keyId"], 32)
        digest(certificate_sha256)
        clients = {info["clientId"]: {info["keyId"]: {"publicKey": info["clientPublicKey"], "certificateSha256": certificate_sha256, "revoked": False}}}
        initial_owner = {"fence": "0", "bootId": b64(bytes(32)), "clientId": info["clientId"]}
        with self.connect() as db:
            db.execute("INSERT INTO deployments VALUES (?,?,?,?,?)", (info["deploymentId"], json.dumps(info["head"]), json.dumps(initial_owner), "0", json.dumps(clients)))

    def execute(self, raw, certificate_sha256):
        wire = decode(raw)
        fields(wire, ["request", "signature"])
        request = wire["request"]
        fields(request, ["version", "deploymentId", "clientId", "keyId", "requestId", "nonce", "operation", "body"])
        if request["version"] != "1":
            raise ValueError("version")
        for name in ["deploymentId", "clientId", "requestId"]:
            uuid(request[name])
        binary(request["keyId"], 32)
        binary(request["nonce"], 32)
        op, body = request["operation"], request["body"]
        if op == "read":
            fields(body, [])
        elif op == "acquire":
            fields(body, ["operationId", "expectedHead", "expectedOwner", "newBootId"])
            binary(body["newBootId"], 32)
        elif op == "advance":
            fields(body, ["operationId", "expectedHead", "expectedOwner", "target"])
            head(body["target"])
        elif op == "authorize":
            fields(body, ["operationId", "expectedHead", "expectedOwner", "kind", "actionDigest", "audience"])
            if body["kind"] not in ["login", "metadata", "reveal", "export", "sync", "external", "local-read"]:
                raise ValueError("authorization kind")
            digest(body["actionDigest"])
            if body["kind"] == "sync":
                uuid(body["audience"])
            elif body["audience"] is not None:
                raise ValueError("audience")
        elif op == "status":
            fields(body, ["operationId", "operationDigest"])
            digest(body["operationDigest"])
        else:
            raise ValueError("operation")
        if op != "read":
            uuid(body["operationId"])
        if op in ["acquire", "advance", "authorize"]:
            head(body["expectedHead"])
            owner(body["expectedOwner"])

        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM deployments WHERE id=?", (request["deploymentId"],)).fetchone()
            if row is None:
                raise PermissionError("unknown deployment")
            clients = json.loads(row["clients"])
            client = clients.get(request["clientId"], {}).get(request["keyId"], {})
            if not client or client["revoked"] or client["certificateSha256"] != certificate_sha256:
                raise PermissionError("client disabled")
            Ed25519PublicKey.from_public_bytes(binary(client["publicKey"], 32)).verify(binary(wire["signature"], 64), b"SYMCON-ANCHOR-REQUEST-V1\0" + canonical(request))
            current_head, current_owner = json.loads(row["head"]), json.loads(row["owner"])
            result = None
            if op != "read":
                operation_digest = body["operationDigest"] if op == "status" else hashlib.sha256(canonical({key: request[key] for key in ["deploymentId", "clientId", "operation", "body"]})).hexdigest()
                prior = db.execute("SELECT * FROM decisions WHERE deployment=? AND operation_id=?", (request["deploymentId"], body["operationId"])).fetchone()
                if prior is not None:
                    if prior["client"] != request["clientId"]:
                        raise PermissionError("foreign operation")
                    if prior["digest"] != operation_digest:
                        result = {"operationId": body["operationId"], "operationDigest": operation_digest, "operation": op if op != "status" else None, "status": "REJECTED", "head": current_head, "owner": current_owner, "actionDigest": None, "reason": "ID_REUSE"}
                    else:
                        result = json.loads(prior["decision"])
                elif op == "status":
                    result = {"operationId": body["operationId"], "operationDigest": operation_digest, "operation": None, "status": "NOT_FOUND", "head": current_head, "owner": current_owner, "actionDigest": None, "reason": "NOT_FOUND"}
                else:
                    reason = "NONE"
                    if body["expectedHead"] != current_head:
                        reason = "HEAD"
                    elif body["expectedOwner"] != current_owner or (op != "acquire" and (current_owner["clientId"] != request["clientId"] or current_owner["fence"] == "0")):
                        reason = "OWNER"
                    if reason == "NONE" and op == "acquire":
                        if int(current_owner["fence"]) >= QMAX:
                            reason = "LIMIT"
                        else:
                            current_owner = {"fence": str(int(current_owner["fence"]) + 1), "bootId": body["newBootId"], "clientId": request["clientId"]}
                    if reason == "NONE" and op == "advance":
                        target = body["target"]
                        if int(current_head["index"]) >= QMAX or target["generation"] != current_head["generation"] or int(target["index"]) != int(current_head["index"]) + 1 or target["commitId"] == current_head["commitId"]:
                            reason = "HEAD"
                        else:
                            current_head = target
                    result = {"operationId": body["operationId"], "operationDigest": operation_digest, "operation": op, "status": "REJECTED" if reason != "NONE" else ("AUTHORIZED" if op == "authorize" else "APPLIED"), "head": current_head, "owner": current_owner, "actionDigest": body.get("actionDigest"), "reason": reason}
                    db.execute("UPDATE deployments SET head=?,owner=? WHERE id=?", (json.dumps(current_head), json.dumps(current_owner), request["deploymentId"]))
                    db.execute("INSERT INTO decisions VALUES (?,?,?,?,?,?)", (request["deploymentId"], body["operationId"], operation_digest, request["clientId"], body.get("audience"), json.dumps(result)))
            db.commit()  # Persist BOTH the decision and state before signing or acknowledging.
            response = {"version": "1", "deploymentId": request["deploymentId"], "requestId": request["requestId"], "nonce": request["nonce"], "requestDigest": hashlib.sha256(canonical(request)).hexdigest(), "anchorKeyId": self.key_id, "head": current_head, "owner": current_owner, "credentialRevision": row["credential_revision"], "result": result}
        return canonical({"response": response, "signature": b64(self.key.sign(b"SYMCON-ANCHOR-RESPONSE-V1\0" + canonical(response)))})


def serve(witness, args):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            self.request.do_handshake()
            super().setup()

        def do_POST(self):
            if self.path != "/v1/anchor" or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                self.send_error(400)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 65536:
                    raise ValueError("size")
                certificate = self.connection.getpeercert(binary_form=True)
                if not certificate:
                    raise PermissionError("client certificate")
                body = witness.execute(self.rfile.read(size), hashlib.sha256(certificate).hexdigest())
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                self.send_response(403)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def log_message(self, *_):
            pass  # Never log bodies, signatures, certificates or authentication headers.

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.load_verify_locations(args.client_ca)
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    provision = commands.add_parser("provision")
    provision.add_argument("--info", required=True)
    provision.add_argument("--certificate-sha256", required=True)
    run = commands.add_parser("serve")
    run.add_argument("--bind", default="127.0.0.1")
    run.add_argument("--port", type=int, default=9443)
    run.add_argument("--cert", required=True)
    run.add_argument("--key", required=True)
    run.add_argument("--client-ca", required=True)
    args = parser.parse_args()
    if args.command == "init":
        print(json.dumps(Witness.initialize(args.directory)))
    elif args.command == "provision":
        Witness(args.directory).provision(json.loads(Path(args.info).read_text()), args.certificate_sha256)
    else:
        serve(Witness(args.directory), args)


if __name__ == "__main__":
    main()
