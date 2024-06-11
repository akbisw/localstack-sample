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

.venv/bin/gunicorn web_api.handler_fargate:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:80 --reload
