#!/usr/bin/env bash

set -e

rm -rf .box-venv
mkdir .box-venv

sandbox -v $(pwd):/pwd -v ~/.mitmproxy:/home/sprrw/.mitmproxy -v $(pwd)/.box-venv:/pwd/.venv --reset-on-done -- bash -c 'cd /pwd; exec bash'
