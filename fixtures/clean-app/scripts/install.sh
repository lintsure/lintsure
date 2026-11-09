#!/bin/sh
# Near miss: download, check the checksum, then run.
curl -fsSLo install.sh https://example.com/install.sh
echo "$EXPECTED_SHA256  install.sh" | sha256sum -c -
sh install.sh
curl -s https://example.com/status | grep ok
