"""Ephemeral Ed25519 CA and mutual TLS identities for bounded local tests."""
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def identities():
    now = datetime.now(timezone.utc)
    root_key = ed25519.Ed25519PrivateKey.generate()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'local-test-ca')])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, None))
    result = {'ca': root.public_bytes(serialization.Encoding.PEM)}
    for role in ('server', 'client'):
        key = ed25519.Ed25519PrivateKey.generate()
        name = 'epe-' + role
        certificate = (x509.CertificateBuilder()
                       .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                       .issuer_name(root_name).public_key(key.public_key())
                       .serial_number(x509.random_serial_number())
                       .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if role == 'server'
                                                           else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                       .sign(root_key, None))
        result[role + '_cert'] = certificate.public_bytes(serialization.Encoding.PEM)
        result[role + '_key'] = key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption())
    return result
