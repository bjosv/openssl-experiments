#!/usr/bin/env bash

mkdir -p tls

# Generate CA.
openssl genrsa -out tls/ca.key 4096
openssl req \
    -x509 -new -nodes -sha256 \
    -key tls/ca.key \
    -days 3650 \
    -subj '/O=Test/CN=Certificate Authority' \
    -out tls/ca.crt

# Generate server private key and certificate.
openssl genrsa -out tls/server.key 2048
openssl req \
    -new -sha256 \
    -key tls/server.key \
    -subj '/O=Test/CN=Server' | \
    openssl x509 \
        -req -sha256 \
        -CA tls/ca.crt \
        -CAkey tls/ca.key \
        -CAserial tls/ca.txt \
        -CAcreateserial \
        -days 1 \
        -out tls/server.crt

# Generate client private key and certificate.
openssl genrsa -out tls/client.key 2048
openssl req \
    -new -sha256 \
    -key tls/client.key \
    -subj '/O=Test/CN=Client' | \
    openssl x509 \
        -req -sha256 \
        -CA tls/ca.crt \
        -CAkey tls/ca.key \
        -CAserial tls/ca.txt \
        -CAcreateserial \
        -days 1 \
        -out tls/client.crt
