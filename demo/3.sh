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
echo "Scanning 3-lang with Trivy (image)"
sleep 2
echo "Scanned 3-lang with Trivy (image)"
echo ""
echo "Scanning 3-lang with Grype (image)"
sleep 2
echo "Scanned 3-lang with Grype (image)"
echo ""
echo "Scanning 3-lang with Docker Scan (image)"
sleep 2
echo "Scanned 3-lang with Docker Scan (image)"
echo ""
echo "Scanning 3-lang with Docker Scout (image)"
sleep 2
echo "Scanned 3-lang with Docker Scout (image)"

p "# View results"
clear
make results-3-lang-table

pe "clear"
