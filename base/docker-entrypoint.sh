#!/bin/bash

PIDFILE_DIR=/var/run/zorp

function create_pidfile_dir {
    mkdir $PIDFILE_DIR
    chown zorp.zorp $PIDFILE_DIR
    chmod 0770 $PIDFILE_DIR
}

create_pidfile_dir

exec "$@"
