# easy-sign

This project provides a command-line tool to generate a self-signed Certificate Authority (CA) certificate and to create certificates signed by that CA. It uses the `cryptography` library to handle cryptographic operations.

## Features

- Generate a self-signed CA certificate.
- Create a certificate signed by a CA.
- Supports password protection for private keys.
- Customizable subject attributes for certificates.

## Requirements

- Python 3.6 or higher
- `cryptography` library

You can install the required library using pip:

```bash
pip install cryptography
```

## Usage

### Generate a CA Certificate

To generate a self-signed CA certificate, use the following command:

```bash
python easy-sign.py ca --filename <prefix> --password <password> [--country <country>] [--state <state>] [--locality <locality>] [--organization <organization>] [--common-name <common name>]
```

#### Example

```bash
python easy-sign.py ca --filename my_ca --password mypassword --country US --state California --locality San Francisco --organization "Example Company" --common-name "My CA"
```

### Generate a Signed Certificate

To generate a certificate signed by a CA, use the following command:

```bash
python easy-sign.py cert --domain <domain> --filename <prefix> --password <password> --ca-key <path to CA key> --ca-cert <path to CA cert> --ca-password <password> [--country <country>] [--state <state>] [--locality <locality>] [--organization <organization>]
```

#### Example

```bash
python easy-sign.py cert --domain example.com --filename my_cert --password mypassword --ca-key my_ca_key.pem --ca-cert my_ca_cert.pem --ca-password mypassword --country US --state California --locality San Francisco --organization "Example Company"
```

## Files Generated

- For CA:
  - `my_ca_cert.pem`: The CA certificate.
  - `my_ca_key.pem`: The CA private key.

- For Signed Certificate:
  - `my_cert_cert.pem`: The signed certificate.
  - `my_cert_key.pem`: The private key for the signed certificate.


## Contributing

Feel free to fork the repository and submit pull requests. Issues and feature requests are welcome!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
