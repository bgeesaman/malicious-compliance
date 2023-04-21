#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Our Dockerfile with moved/symlinked software dependency files"

echo "cat Dockerfile-3-lang" 
bat docker/Dockerfile-3-lang -H 14:38

p "# Build the modified image"
make build-3-lang

pe "clear"

p "# Scan the image"
echo "Scanning 3-lang with Trivy"
sleep 1
echo "Scanned 3-lang with Trivy"
echo ""
echo "Scanning 3-lang with Grype"
sleep 1
echo "Scanned 3-lang with Grype"
echo ""
echo "Scanning 3-lang with Docker Scan"
sleep 1
echo "Scanned 3-lang with Docker Scan"
echo ""
echo "Scanning 3-lang with Docker Scout"
sleep 1
echo "Scanned 3-lang with Docker Scout"

p "# View results"
clear
make results-3-lang-table

pe "# end"
clear
