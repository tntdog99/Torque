#!/usr/bin/env bash
set -euo pipefail

rm -rf client1 client2

mkdir -p client1 client2

cp -R cli_client/. client1/
cp -R cli_client/. client2/
cp -R kivy_client/. client3/

cp -R shared/. client1/
cp -R shared/. client2/
cp -R shared/. client3/


