#!/bin/bash -e

ZORP_PIDFILE_DIR=/var/run/zorp

function create_pidfile_dir {
    mkdir $ZORP_PIDFILE_DIR
    chown zorp.zorp $ZORP_PIDFILE_DIR
    chmod 0770 $ZORP_PIDFILE_DIR
}

create_pidfile_dir

exec "$@"
