#!/bin/bash

#### For testing purposes only####

# Create private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/privatekey.pem
echo "Created keys/privatekey.pem"

# Create public key
openssl rsa -in keys/privatekey.pem -pubout -out keys/publickey.pem
echo "Created keys/publickey.pem"

# Create Certificate Signing Request (CSR)
openssl req -new -newkey rsa:2048 -nodes -keyout ca/private/ca.key -out ca_csr.pem
echo "Created ca/private/ca.key"

# Sign the CSR with the CA private key to create a CA certificate for testing
openssl x509 -signkey ca/private/ca.key -in ca_csr.pem -req -days 1200 -out ca/certs/ca.pem
echo "Created ca/certs/ca.pem"

echo "Successfully created keypairs and CA certificate"



