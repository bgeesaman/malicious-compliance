#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Our Dockerfile using all techniques squashed into a single layer"

echo "cat Dockerfile-5-zero" 
bat docker/Dockerfile-5-zero -H 1:1 -H 26:28 -H 58:59

p "# Build the modified image"
make build-5-zero

pe "docker images sig-honk/malicious-compliance:4-bin"
pe "docker images sig-honk/malicious-compliance:5-zero"

pe "clear"

p "# Scan the image"
echo "Scanning 5-zero with Trivy"
sleep 1
echo "Scanned 5-zero with Trivy"
echo ""
echo "Scanning 5-zero with Grype"
sleep 1
echo "Scanned 5-zero with Grype"
echo ""
echo "Scanning 5-zero with Docker Scan"
sleep 1
echo "Scanned 5-zero with Docker Scan"
echo ""
echo "Scanning 5-zero with Docker Scout"
sleep 1
echo "Scanned 5-zero with Docker Scout"

p "# View results"
clear
make results-5-zero-table

pe "# end"
clear
