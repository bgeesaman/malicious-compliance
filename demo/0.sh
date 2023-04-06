#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Our base Dockerfile"

p "cat Dockerfile-0-base" 
bat docker/Dockerfile-0-base -H 3:8

p "# Build the base image"
make build-0-base

pe "clear"

pe "docker images sig-honk/malicious-compliance:0-base"

p "# Scan the image"
echo "Scanning 0-base with Trivy (image)"
sleep 2
echo "Scanned 0-base with Trivy (image)"
echo ""
echo "Scanning 0-base with Grype (image)"
sleep 2
echo "Scanned 0-base with Grype (image)"
echo ""
echo "Scanning 0-base with Docker Scan (image)"
sleep 2
echo "Scanned 0-base with Docker Scan (image)"
echo ""
echo "Scanning 0-base with Docker Scout (image)"
sleep 2
echo "Scanned 0-base with Docker Scout (image)"

p "# View results"
clear
make results-0-base | bat -l json --style "plain" --theme "Coldark-Dark"

p "# Summary"
clear
make results-0-base-table
