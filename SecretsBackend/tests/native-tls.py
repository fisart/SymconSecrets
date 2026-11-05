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
import time
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
            mode = getattr(self.server, 'reply_mode', 'normal')
            if mode == 'slow-headers':
                time.sleep(2.2)
            response = b'{"received":true}' if mode != 'oversize' else b'x' * 65537
            self.send_response(302 if mode == 'redirect' else 200)
            if mode == 'redirect':
                self.send_header('Location', '/hook/secrets_peer_12345')
            if mode == 'chunked':
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                self.wfile.write(b'8\r\n{"receiv\r\n9\r\ned":true}\r\n0\r\n\r\n')
                return
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response) + (10 if mode == 'truncated' else 0)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                if mode != 'slow-headers':
                    raise

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
        server.fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
        return server, 'https://127.0.0.1:' + str(server.server_port) + '/hook/secrets_peer_12345'

    def request(url, settings=(), mode='', environment=None):
        cmd = command + [item for setting in settings for item in ['-d', setting]]
        result = subprocess.run(cmd + [str(root / 'SecretsBackend/tests/native-tls-client.php'), url, mode],
                                env=environment or env, text=True, capture_output=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr
        try:
            return json.loads(result.stdout)
        except ValueError as error:
            raise AssertionError(result.stdout + result.stderr) from error

    server, url = run_server()
    try:
        before = len(counts)
        debug = request(url, ['openssl.cafile=' + str(other_path)], mode='diagnose')
        assert not debug['authenticatedHandshake']['ok'], debug
        assert debug['certificateObservation']['handshakeSucceeded'], debug
        assert debug['certificateObservation']['authenticated'] is False, debug
        chain = debug['certificateObservation']['certificates']
        assert len(chain) == 2 and chain[0]['sha256'] == server.fingerprint, debug
        assert chain[0]['issuerSignatureFoundInPresentedChainOrConfiguredFile'], debug
        assert not chain[1]['issuerSignatureFoundInPresentedChainOrConfiguredFile'], debug
        assert debug['configuredCA']['certificateCount'] == 1, debug
        assert debug['authenticatedHandshake']['errors']['opensslCodes'], debug
        assert str(folder) not in json.dumps(debug), 'Local paths leaked into support report.'
        assert len(counts) == before, 'TLS diagnostics sent an HTTP request.'
        valid_debug = request(url, ['openssl.cafile=' + str(ca_path)], mode='diagnose')
        assert valid_debug['authenticatedHandshake']['ok'], valid_debug
        assert valid_debug['certificateObservation']['certificates'][1]['issuerSignatureFoundInPresentedChainOrConfiguredFile'], valid_debug
        assert len(counts) == before, 'Successful TLS diagnostics sent HTTP.'
        old = request(url, mode='baseline')
        assert not old['ok'] and old['curlCode'] == 60, old
        fixed = request(url, ['openssl.cafile=' + str(ca_path)])
        assert fixed['ok'] and fixed['body'] == '{"received":true}', fixed
        explicit = request(url, ['curl.cainfo=' + str(ca_path)])
        assert not explicit['ok'], explicit  # PHP streams use OpenSSL trust, never cURL's separate file.
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
        assert wrong['ok'], wrong  # Same split as reported deployment: cURL file must not override working OpenSSL trust.
        before = len(counts)
        missing = request(url, ['openssl.cafile=' + str(folder / 'missing.pem')])
        assert not missing['ok'], missing
        unrelated = request(url, ['openssl.cafile=' + str(other_path)])
        assert not unrelated['ok'] and unrelated['problem'] == 'certificate', unrelated
        assert len(counts) == before, 'A request was sent after failed certificate verification.'
        pinned = request(url, mode='pin:' + server.fingerprint)
        assert pinned['ok'], pinned
        before = len(counts)
        mismatch = request(url, mode='pin:' + '0' * 64)
        assert not mismatch['ok'] and mismatch['problem'] == 'certificate', mismatch
        assert len(counts) == before, 'Fingerprint mismatch sent HTTP data before authentication.'
        server.reply_mode = 'slow-headers'
        short = request(url, ['openssl.cafile=' + str(ca_path)], mode='timeout:1.5')
        assert not short['ok'] and short['problem'] == 'timeout', short
        relay = request(url, ['openssl.cafile=' + str(ca_path)], mode='timeout:6')
        assert relay['ok'] and relay['body'] == '{"received":true}', relay
        server.reply_mode = 'chunked'
        chunked = request(url, ['openssl.cafile=' + str(ca_path)])
        assert chunked['ok'] and chunked['body'] == '{"received":true}', chunked
        for mode, problem in [('redirect', 'http'), ('oversize', 'response-size'), ('truncated', 'unconfirmed')]:
            server.reply_mode = mode
            before = len(counts)
            result = request(url, ['openssl.cafile=' + str(ca_path)])
            assert not result['ok'] and result['problem'] == problem, result
            assert len(counts) == before + 1, 'HTTP redirect was followed.'
    finally:
        server.shutdown()
        server.server_close()

    issuer_path = folder / 'issuer.pem'
    issuer_path.write_bytes(intermediate.public_bytes(serialization.Encoding.PEM))
    for options in [dict(san=False), dict(expired=True), dict(chain=False)]:
        server, url = run_server(**options)
        try:
            before = len(counts)
            refused = request(url, ['openssl.cafile=' + str(ca_path)])
            assert not refused['ok'] and refused['problem'] == 'certificate', refused
            assert len(counts) == before, 'A failed TLS identity/chain reached the application.'
            completed = request(url, ['openssl.cafile=' + str(ca_path)], mode='issuers:' + str(issuer_path))
            if options == dict(chain=False):
                assert completed['ok'], completed
                assert len(counts) == before + 1, counts
                before = len(counts)
            else:
                assert not completed['ok'], completed
                assert len(counts) == before, 'Issuer completion bypassed name or date validation.'
            untrusted = request(url, ['openssl.cafile=' + str(other_path)], mode='issuers:' + str(issuer_path))
            assert not untrusted['ok'], untrusted
            assert len(counts) == before, 'A supplied intermediate became a new trust anchor.'
        finally:
            server.shutdown()
            server.server_close()
    assert counts == [b'TLS-REQUEST-CANARY'] * 12, counts
print('PASS real HTTPS: reused original PHP streams; explicit approved pin succeeds and mismatch sends no HTTP; separate cURL CA file cannot override OpenSSL;  reproduced unknown-issuer failure, recovered through PHP/env trust, accepted valid chains, rejected wrong roots/hostname/expiry/incomplete chain before POST, no trust-policy bypass')
