#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Let's show our scanners and their versions"
pe "trivy -v"
pe "syft --version"
pe "grype version"
p "docker scan --version"
docker scan --version 2> /dev/null
pe "docker scout version"

pe "clear"

p "# Our base Dockerfile"

p "cat Dockerfile-0-base" 
bat docker/Dockerfile-0-base -H 3:8

p "# Build the base image"
make build-0-base

pe "clear"

pe "docker images sig-honk/malicious-compliance:0-base"

p "# Scan the image"
echo "Scanning 0-base with Trivy"
sleep 2
echo "Scanned 0-base with Trivy"
echo ""
echo "Scanning 0-base with Grype"
sleep 2
echo "Scanned 0-base with Grype"
echo ""
echo "Scanning 0-base with Docker Scan"
sleep 2
echo "Scanned 0-base with Docker Scan"
echo ""
echo "Scanning 0-base with Docker Scout"
sleep 2
echo "Scanned 0-base with Docker Scout"

p "# View results"
clear
make results-0-base | bat -l json --style "plain" --theme "Coldark-Dark"

p "# Summary"
clear
make results-0-base-table
