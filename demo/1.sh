#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Our Dockerfile with changed/deleted OS release files in /etc"

echo "cat Dockerfile-1-os" 
bat docker/Dockerfile-1-os -H 17:20

p "# Build the modified image"
make build-1-os

pe "clear"

p "# Scan the image"
echo "Scanning 1-os with Trivy"
sleep 1
echo "Scanned 1-os with Trivy"
echo ""
echo "Scanning 1-os with Grype"
sleep 1
echo "Scanned 1-os with Grype"
echo ""
echo "Scanning 1-os with Docker Scan"
sleep 1
echo "Scanned 1-os with Docker Scan"
echo ""
echo "Scanning 1-os with Docker Scout"
sleep 1
echo "Scanned 1-os with Docker Scout"

p "# View results"
clear
make results-1-os-table

pe "# end"
clear
