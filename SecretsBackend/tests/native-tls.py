"""Real loopback HTTPS checks: valid chains recover; false identity and invalid trust never do."""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

parser = argparse.ArgumentParser()
parser.add_argument('--php', default='php')
parser.add_argument('--curl-extension')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
command = [args.php] + (['-n', '-d', 'extension=' + args.curl_extension] if args.curl_extension else [])
command += ['-d', 'openssl.cafile=', '-d', 'openssl.capath=', '-d', 'curl.cainfo=']
probe = subprocess.check_output(command + ['-r', "echo json_encode(['curl'=>function_exists('curl_init'),'openssl'=>function_exists('openssl_x509_read')]);"], text=True)
if not all(json.loads(probe).values()):
    raise SystemExit('Real TLS fixture needs supplied PHP cURL and OpenSSL.')
env = dict(os.environ)
for key in list(env):
    if 'proxy' in key.lower() or key in ['SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE']:
        env.pop(key, None)
env['NO_PROXY'] = '127.0.0.1,localhost'
now = dt.datetime.now(dt.timezone.utc)

def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def cert(subject, public, issuer, signing, *, ca=False, san=True, expired=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name)
               .public_key(public).serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=3))
               .not_valid_after(now + dt.timedelta(days=-1 if expired else 30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=not ca, data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True))
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))] if san else [x509.DNSName('other.example')]), critical=False)
    return builder.sign(signing, hashes.SHA256())

with tempfile.TemporaryDirectory(prefix='sec-native-tls-') as raw:
    folder = Path(raw)
    ca_key, intermediate_key = key(), key()
    ca = cert('Fixture root', ca_key.public_key(), None, ca_key, ca=True)
    intermediate = cert('Fixture intermediate', intermediate_key.public_key(), ca.subject, ca_key, ca=True)
    ca_path = folder / 'root.pem'
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    other_key = key()
    other_ca = cert('Unrelated root', other_key.public_key(), None, other_key, ca=True)
    other_path = folder / 'other.pem'
    other_path.write_bytes(other_ca.public_bytes(serialization.Encoding.PEM))
    counts = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *unused):
            pass

        def do_POST(self):
            counts.append(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
            response = b'{"received":true}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    def run_server(*, san=True, expired=False, chain=True):
        leaf_key = key()
        leaf = cert('Fixture server', leaf_key.public_key(), intermediate.subject, intermediate_key,
                    san=san, expired=expired)
        chain_path, key_path = folder / 'server.pem', folder / 'key.pem'
        chain_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) +
                              (intermediate.public_bytes(serialization.Encoding.PEM) if chain else b''))
        key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(chain_path, key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, 'https://127.0.0.1:' + str(server.server_port) + '/hook/secrets_peer_12345'

    def request(url, settings=(), mode='', environment=None):
        cmd = command + [item for setting in settings for item in ['-d', setting]]
        result = subprocess.run(cmd + [str(root / 'SecretsBackend/tests/native-tls-client.php'), url, mode],
                                env=environment or env, text=True, capture_output=True, timeout=15, check=True)
        try:
            return json.loads(result.stdout)
        except ValueError as error:
            raise AssertionError(result.stdout + result.stderr) from error

    server, url = run_server()
    try:
        old = request(url, mode='baseline')
        assert not old['ok'] and old['curlCode'] == 60, old
        fixed = request(url, ['openssl.cafile=' + str(ca_path)])
        assert fixed['ok'] and fixed['body'] == '{"received":true}', fixed
        explicit = request(url, ['curl.cainfo=' + str(ca_path)])
        assert explicit['ok'], explicit
        inherited = request(url, environment={**env, 'SSL_CERT_FILE': str(ca_path)})
        assert inherited['ok'], inherited
        directory = folder / 'hashed'
        directory.mkdir()
        root_hash = subprocess.check_output(command + ['-r', 'echo openssl_x509_parse(file_get_contents($argv[1]))["hash"];', str(ca_path)], env=env, text=True).strip()
        (directory / (root_hash + '.0')).write_bytes(ca_path.read_bytes())
        directory_result = request(url, ['openssl.capath=' + str(directory)])
        assert directory_result['ok'], directory_result
        before = len(counts)
        wrong = request(url, ['curl.cainfo=' + str(other_path), 'openssl.cafile=' + str(ca_path)])
        assert not wrong['ok'] and wrong['curlCode'] == 60, wrong
        missing = request(url, ['curl.cainfo=' + str(folder / 'missing.pem')])
        assert not missing['ok'] and missing['reason'] == 'ca-store-unavailable', missing
        assert len(counts) == before, 'A request was sent after failed certificate verification.'
    finally:
        server.shutdown()
        server.server_close()

    for options in [dict(san=False), dict(expired=True), dict(chain=False)]:
        server, url = run_server(**options)
        try:
            before = len(counts)
            refused = request(url, ['openssl.cafile=' + str(ca_path)])
            assert not refused['ok'] and refused['curlCode'] == 60, refused
            assert len(counts) == before, 'A failed TLS identity/chain reached the application.'
        finally:
            server.shutdown()
            server.server_close()
    assert counts == [b'TLS-REQUEST-CANARY'] * 4, counts
print('PASS real HTTPS: reproduced unknown-issuer failure, recovered through PHP/env trust, accepted valid chains, rejected wrong roots/hostname/expiry/incomplete chain before POST, no trust-policy bypass')
