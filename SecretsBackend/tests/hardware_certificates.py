"""Synthetic test PKI only; never suitable as production hardware trust material."""
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

p=Path(sys.argv[1]);p.mkdir(mode=0o700,parents=True,exist_ok=True)
now=datetime.now(timezone.utc)
def name(label,attester=False):
    entries=[x509.NameAttribute(NameOID.COMMON_NAME,label)]
    if attester:
        entries.extend([x509.NameAttribute(NameOID.COUNTRY_NAME,'DE'),x509.NameAttribute(NameOID.ORGANIZATION_NAME,'Synthetic test attester'),x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,'Authenticator Attestation')])
    return x509.Name(entries)
def cert(label,key,issuer=None,issuer_key=None,ca=True,model=None,expired=False,profile=True):
    subject=name(label,not ca and profile)
    builder=(x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(days=30)).not_valid_after(now+timedelta(days=-1 if expired else 30))
        .add_extension(x509.BasicConstraints(ca=ca,path_length=None),critical=True))
    if model is not None:
        builder=builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4'),b'\x04\x10'+model),critical=False)
    return builder.sign(issuer_key or key,hashes.SHA256())
def save(label,key,certificate):
    (p/(label+'.der')).write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    (p/(label+'.pem')).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (p/(label+'.key')).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (p/(label+'.key')).chmod(0o600)
root_key=ec.generate_private_key(ec.SECP256R1());root=cert('Approved root',root_key);save('approved',root_key,root)
rogue_key=ec.generate_private_key(ec.SECP256R1());rogue=cert('Rogue root without SKI or AKI',rogue_key);save('rogue',rogue_key,rogue)
intermediate_key=ec.generate_private_key(ec.SECP256R1());intermediate=cert('Approved intermediate',intermediate_key,root.subject,root_key);save('intermediate',intermediate_key,intermediate)
for label,issuer,issuer_key,options in [
    ('valid',root,root_key,{}),('valid-intermediate',intermediate,intermediate_key,{}),
    ('rogue-leaf',rogue,rogue_key,{}),('expired',root,root_key,{'expired':True}),
    ('wrong-model',root,root_key,{'model':b'\x43'*16}),('missing-model',root,root_key,{'model':None}),
    ('wrong-subject',root,root_key,{'profile':False}),('ca-leaf',root,root_key,{'ca':True})]:
    key=ec.generate_private_key(ec.SECP256R1());kwargs={'ca':False,'model':b'\x42'*16}|options
    save(label,key,cert(label,key,issuer.subject,issuer_key,**kwargs))
(p/'roots').mkdir(mode=0o700,exist_ok=True)
(p/'roots/approved.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
