#!/bin/bash
set -e

mkdir -p certs
cd certs

echo "Generating CA..."
openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout ca.key -out ca.crt -subj "/C=US/ST=State/L=City/O=SecureVault/CN=SecureVaultCA"

echo "Generating Server Certificate..."
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=US/ST=State/L=City/O=SecureVault/CN=localhost"
openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

echo "Generating Client Certificate..."
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/C=US/ST=State/L=City/O=SecureVaultAgent/CN=ClientAgent"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

echo "Certificates generated successfully in ./certs/"
ls -la
