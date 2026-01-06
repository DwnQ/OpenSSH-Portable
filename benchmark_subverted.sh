#!/bin/bash

CLIENT="/opt/customsshClient/bin/ssh"
HOST="127.0.0.1"
PORT=2222
USER="root"

mkdir -p benchmark_subverted

for i in $(seq -f "%04g" 1 1000); do
    LOGFILE="benchmark_subverted/conn_$i.log"

    $CLIENT \
        -p $PORT \
        -vvv \
        -oBatchMode=yes \
        -oStrictHostKeyChecking=no \
        -oUserKnownHostsFile=/dev/null \
        -oKexAlgorithms=mlkemcustom-sha256 \
        -oHostKeyAlgorithms=pqc-falcon512 \
        -oPubkeyAcceptedAlgorithms=pqc-falcon512 \
        -oIdentityFile=~/.ssh/id_falcon512 \
        $USER@$HOST \
        "echo ok" \
        >"$LOGFILE" 2>&1
done