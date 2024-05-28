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

python -m http.server 8080
