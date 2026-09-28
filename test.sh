#!/usr/bin/env bash

set -e

rm -rf .box-venv
mkdir .box-venv

box -v $(pwd):/pwd -v ~/.mitmproxy:/home/sprrw/.mitmproxy -v $(pwd)/.box-venv:/pwd/.venv -- bash -c 'cd /pwd; exec bash'
