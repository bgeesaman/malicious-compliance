#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Our Dockerfile with deleted Alpine OS Package Metadata"

p "cat Dockerfile-2-pkg" 
bat docker/Dockerfile-2-pkg -H 15:17

p "# Build the modified image"
make build-2-pkg

pe "clear"

pe "docker images sig-honk/malicious-compliance:2-pkg"

p "# Scan the image"
echo "Scanning 2-pkg with Trivy (image)"
sleep 2
echo "Scanned 2-pkg with Trivy (image)"
echo ""
echo "Scanning 2-pkg with Grype (image)"
sleep 2
echo "Scanned 2-pkg with Grype (image)"
echo ""
echo "Scanning 2-pkg with Docker Scan (image)"
sleep 2
echo "Scanned 2-pkg with Docker Scan (image)"
echo ""
echo "Scanning 2-pkg with Docker Scout (image)"
sleep 2
echo "Scanned 2-pkg with Docker Scout (image)"

p "# View results"
clear
make results-2-pkg-table

pe "clear"
