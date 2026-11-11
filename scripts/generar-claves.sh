#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'Uso: %s DIRECTORIO_NUEVO\n' "$0" >&2
  exit 1
fi

# Un directorio nuevo evita reemplazar un par utilizado por tokens vigentes.
umask 077
key_dir=$1
mkdir -m 700 -- "$key_dir"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$key_dir/jwt-private.pem"
openssl pkey -in "$key_dir/jwt-private.pem" -pubout \
  -out "$key_dir/jwt-public.pem"
printf 'Par RSA creado. Conservar la privada solo en security-service y distribuir únicamente la pública.\n'
