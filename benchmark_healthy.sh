#!/bin/bash

CLIENT="/opt/customsshClient/bin/ssh"
HOST="127.0.0.1"
PORT=2222
USER="root"

mkdir -p benchmark_original

for i in $(seq -f "%04g" 1 1000); do
    LOGFILE="benchmark_original/conn_$i.log"

    $CLIENT \
        -p $PORT \
        -vvv \
        -oBatchMode=yes \
        -oStrictHostKeyChecking=no \
        -oUserKnownHostsFile=/dev/null \
        -oKexAlgorithms=mlkem768x25519-sha256 \
        -oHostKeyAlgorithms=ssh-ed25519 \
        -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
        -oIdentityFile=~/.ssh/id_ed25519\
        $USER@$HOST \
        "echo ok" \
        >"$LOGFILE" 2>&1
done

