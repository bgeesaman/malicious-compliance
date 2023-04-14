#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "go version -m /bin/kubectl"
go version -m `which kubectl` | less

p "# Our Dockerfile with Moved/Symlinked Shared Libraries and UPX Packed Binaries"

p "cat Dockerfile-4-bin" 
bat docker/Dockerfile-4-bin -H 3:3 -H 24:39

p "# Build the modified image"
make build-4-bin

pe "clear"

pe "docker images sig-honk/malicious-compliance:4-bin"

p "# Scan the image"
echo "Scanning 4-bin with Trivy"
sleep 2
echo "Scanned 4-bin with Trivy"
echo ""
echo "Scanning 4-bin with Grype"
sleep 2
echo "Scanned 4-bin with Grype"
echo ""
echo "Scanning 4-bin with Docker Scan"
sleep 2
echo "Scanned 4-bin with Docker Scan"
echo ""
echo "Scanning 4-bin with Docker Scout"
sleep 2
echo "Scanned 4-bin with Docker Scout"

p "# View results"
clear
make results-4-bin-table

pe "clear"
