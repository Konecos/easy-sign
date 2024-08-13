import argparse
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.backends import default_backend
import datetime

def generate_ca_certificate(args):
    # Generate private key for CA
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Build CA subject
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, args.country or u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, args.state or u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, args.locality or u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.organization or u"Example Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, args.common_name or u"My CA"),
    ])

    # Create CA certificate
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_subject
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    # Write CA private key to file
    ca_key_file = f"{args.filename}_ca_key.pem"
    ca_cert_file = f"{args.filename}_ca_cert.pem"
    
    with open(ca_key_file, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=BestAvailableEncryption(args.password.encode())
        ))

    # Write CA certificate to file
    with open(ca_cert_file, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    os.chmod(ca_key_file, 0o600)
    os.chmod(ca_cert_file, 0o600)

    print(f"CA certificate and key saved as {ca_cert_file} and {ca_key_file}")

def generate_certificate(args):
    # Load CA certificate and private key
    with open(args.ca_key, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=args.ca_password.encode(),
            backend=default_backend()
        )

    with open(args.ca_cert, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Generate private key for the new certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Build certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, args.country or u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, args.state or u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, args.locality or u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.organization or u"Example Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, args.domain),
    ])

    # Create certificate signed by CA
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(args.domain)]),
        critical=False,
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    # Write private key to file
    key_file = f"{args.filename}_key.pem"
    cert_file = f"{args.filename}_cert.pem"
    
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=BestAvailableEncryption(args.password.encode())
        ))

    # Write certificate to file
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    os.chmod(key_file, 0o600)
    os.chmod(cert_file, 0o600)

    print(f"Certificate and key saved as {cert_file} and {key_file}")

def main():
    parser = argparse.ArgumentParser(description="Generate a self-signed CA or a certificate signed by a CA.")
    subparsers = parser.add_subparsers(dest="command")

    ca_parser = subparsers.add_parser("ca", help="Generate a self-signed CA certificate")
    ca_parser.add_argument("--filename", required=True, help="Output filename prefix")
    ca_parser.add_argument("--password", required=True, help="Password for the CA private key")
    ca_parser.add_argument("--country", help="Country Name (C)")
    ca_parser.add_argument("--state", help="State or Province Name (ST)")
    ca_parser.add_argument("--locality", help="Locality Name (L)")
    ca_parser.add_argument("--organization", help="Organization Name (O)")
    ca_parser.add_argument("--common-name", help="Common Name (CN) for CA")

    cert_parser = subparsers.add_parser("cert", help="Generate a certificate signed by a CA")
    cert_parser.add_argument("--domain", required=True, help="Domain name for the certificate")
    cert_parser.add_argument("--filename", required=True, help="Output filename prefix")
    cert_parser.add_argument("--password", required=True, help="Password for the private key")
    cert_parser.add_argument("--country", help="Country Name (C)")
    cert_parser.add_argument("--state", help="State or Province Name (ST)")
    cert_parser.add_argument("--locality", help="Locality Name (L)")
    cert_parser.add_argument("--organization", help="Organization Name (O)")
    cert_parser.add_argument("--ca-key", required=True, help="CA private key file")
    cert_parser.add_argument("--ca-cert", required=True, help="CA certificate file")
    cert_parser.add_argument("--ca-password", required=True, help="Password for the CA private key")

    args = parser.parse_args()

    if args.command == "ca":
        generate_ca_certificate(args)
    elif args.command == "cert":
        generate_certificate(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()