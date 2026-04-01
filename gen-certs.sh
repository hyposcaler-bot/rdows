#!/bin/sh
# Generate self-signed TLS certificates for RDoWS development.
# Outputs server.crt and server.key in the current directory.

set -e

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout server.key \
    -out server.crt \
    -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Generated server.crt and server.key for localhost"
echo ""
echo "Start the server:"
echo "  cargo run -p rdows-server -- --bind 127.0.0.1:9443 --cert server.crt --key server.key"
