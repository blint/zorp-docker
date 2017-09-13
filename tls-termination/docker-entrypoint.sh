#!/bin/bash -e

ZORP_PIDFILE_DIR=/var/run/zorp

function create_pidfile_dir {
    mkdir $ZORP_PIDFILE_DIR
    chown zorp.zorp $ZORP_PIDFILE_DIR
    chmod 0770 $ZORP_PIDFILE_DIR
}

create_pidfile_dir

function create_cert_digest_file {
    ZORP_CERT_FILE_DIR=/etc/zorp/certs
    awk 'BEGIN{n=1} (n==1) {print}/-----END CERTIFICATE-----/ {n++}' ${ZORP_CERT_FILE_DIR}/fullchain.pem | \
    openssl x509 -pubkey -noout -in /dev/stdin | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64 >${ZORP_CERT_FILE_DIR}/cert.dgst
    awk 'BEGIN{n=1} (n==2) {print}/-----END CERTIFICATE-----/ {n++}' ${ZORP_CERT_FILE_DIR}/fullchain.pem | \
    openssl x509 -pubkey -noout -in /dev/stdin | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64 >${ZORP_CERT_FILE_DIR}/ca.dgst
}

create_cert_digest_file

exec "$@"
