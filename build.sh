#!/bin/bash

set -e

echo "[build] capture-service..."

cd "$(dirname "$0")/capture-service"

cargo build --bin capture-service

echo "[run] capture-service..."

exec sudo -E /home/netmon/retina/target/debug/capture-service \
    -c /home/netmon/retina/deepak/services/capture-service/config.toml