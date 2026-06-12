#!/bin/bash

# Define the InfluxDB connection details
export TEAMS_QOE_INFLUX_URL="http://10.238.80.90:8087/api/v2/write?org=teams&bucket=qoe&precision=ns"
export TEAMS_QOE_INFLUX_TOKEN="ufPzzTY6xA8_z-1685fhbAqr5K73F5-FO6x-JMdNnmH_zrKa0NU15J49by2BlC-_oMpfUxNj51e1zMxRUWF4JA=="

echo "Starting Teams QoE Capture Engine..."
echo "Exporting data to: $TEAMS_QOE_INFLUX_URL"

# Run the capture engine preserving the environment variables (-E)
sudo -E /home/netmon/retina/target/debug/capture-service -c /home/netmon/retina/deepak/services/capture-service/config.toml
