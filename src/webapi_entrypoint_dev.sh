#!/bin/sh

# enable legacy algorithms in openssl

cat <<EOT >> /etc/pki/tls/openssl.cnf
[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
EOT

uvicorn web_api.handler_fargate:app --host 0.0.0.0 --port 80 --reload
