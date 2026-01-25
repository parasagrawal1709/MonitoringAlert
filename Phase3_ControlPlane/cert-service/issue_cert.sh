#!/bin/bash
set -euo pipefail

echo "Running certificate issuance..."
# Example: replace with your actual acme.sh commands
acme.sh --issue --dns dns_duckdns -d akssltest.duckdns.org --dnssleep 90

echo "Done!"
