#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""
p "# Our Dockerfile with moved/symlinked shared libraries and UPX packed binaries"

echo "cat Dockerfile-4-bin" 
bat docker/Dockerfile-4-bin -H 3:3 -H 40:53

p "# Build the modified image"
make build-4-bin

pe "clear"

p "# Scan the image"
echo "Scanning 4-bin with Trivy"
sleep 1
echo "Scanned 4-bin with Trivy"
echo ""
echo "Scanning 4-bin with Grype"
sleep 1
echo "Scanned 4-bin with Grype"
echo ""
echo "Scanning 4-bin with Docker Scan"
sleep 1
echo "Scanned 4-bin with Docker Scan"
echo ""
echo "Scanning 4-bin with Docker Scout"
sleep 2
echo "Scanned 4-bin with Docker Scout"

p "# View results"
clear
make results-4-bin-table

pe "# end"
clear
