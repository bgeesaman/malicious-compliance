#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Our Dockerfile with Moved/Symlinked Shared Libraries and UPX Packed Binaries"

p "cat Dockerfile-4-bin" 
bat docker/Dockerfile-4-bin -H 3:3 -H 24:39

p "# Build the modified image"
make build-4-bin

pe "clear"

pe "docker images sig-honk/malicious-compliance:4-bin"

p "# Scan the image"
echo "Scanning 4-bin with Trivy (image)"
sleep 2
echo "Scanned 4-bin with Trivy (image)"
echo ""
echo "Scanning 4-bin with Grype (image)"
sleep 2
echo "Scanned 4-bin with Grype (image)"
echo ""
echo "Scanning 4-bin with Docker Scan (image)"
sleep 2
echo "Scanned 4-bin with Docker Scan (image)"
echo ""
echo "Scanning 4-bin with Docker Scout (image)"
sleep 2
echo "Scanned 4-bin with Docker Scout (image)"

p "# View results"
clear
make results-4-bin-table

pe "clear"
