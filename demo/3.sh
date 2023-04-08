#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Our Dockerfile with Moved/Symlinked Language Runtime Dependency Files"

p "cat Dockerfile-3-lang" 
bat docker/Dockerfile-3-lang -H 3:15

p "# Build the modified image"
make build-3-lang

pe "clear"

pe "docker images sig-honk/malicious-compliance:3-lang"

p "# Scan the image"
echo "Scanning 3-lang with Trivy"
sleep 2
echo "Scanned 3-lang with Trivy"
echo ""
echo "Scanning 3-lang with Grype"
sleep 2
echo "Scanned 3-lang with Grype"
echo ""
echo "Scanning 3-lang with Docker Scan"
sleep 2
echo "Scanned 3-lang with Docker Scan"
echo ""
echo "Scanning 3-lang with Docker Scout"
sleep 2
echo "Scanned 3-lang with Docker Scout"

p "# View results"
clear
make results-3-lang-table

pe "clear"
