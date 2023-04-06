#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Our Dockerfile with changed/deleted OS Release files in /etc"

p "cat Dockerfile-1-os" 
bat docker/Dockerfile-1-os -H 10:13

p "# Build the modified image"
make build-1-os

pe "clear"

pe "docker images sig-honk/malicious-compliance:1-os"

p "# Scan the image"
echo "Scanning 1-os with Trivy (image)"
sleep 2
echo "Scanned 1-os with Trivy (image)"
echo ""
echo "Scanning 1-os with Grype (image)"
sleep 2
echo "Scanned 1-os with Grype (image)"
echo ""
echo "Scanning 1-os with Docker Scan (image)"
sleep 2
echo "Scanned 1-os with Docker Scan (image)"
echo ""
echo "Scanning 1-os with Docker Scout (image)"
sleep 2
echo "Scanned 1-os with Docker Scout (image)"

p "# View results"
clear
make results-1-os-table

pe "clear"
