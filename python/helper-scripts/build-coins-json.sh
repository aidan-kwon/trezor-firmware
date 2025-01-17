#!/bin/bash
cd $(dirname $0)/..

DEST=trezorlib/coins.json

BUILD_COINS_AT="../common/tools/cointool.py dump \
    --list --support \
    --include-type=misc \
    --exclude=icon \
    -o \
"

if [ "$1" == "--check" ]; then
    TMP=$(mktemp)
    $BUILD_COINS_AT $TMP
    diff -q $DEST $TMP
    if [ "$?" -ne 0 ]; then
        echo "Please run $0"
    fi
    rm $TMP
    exit $ERR
else
    $BUILD_COINS_AT $DEST
fi
