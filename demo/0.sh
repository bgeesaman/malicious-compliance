#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Let's show our scanners and their versions"
echo "trivy -v"
echo "Version: 0.37.1"
echo ""
sleep 0.6
echo "grype version"
echo "Application:          grype"
echo "Version:              0.56.0"
echo ""
sleep 0.6
echo "docker scan --version"
echo "Version:    v0.25.0"
echo "Git commit: 284fb08"
echo "Provider:   Snyk (1.1064.0)"
echo ""
sleep 0.6
echo "docker scout version"
echo "version: v0.6.0 (go1.19.5 - darwin/amd64)"
echo "git commit: aabe2bfd192f7ac8cbfa4afea647b4dc41d3d30d"
echo ""

pe "clear"

p "# Our base Dockerfile"

echo "cat Dockerfile-0-base"
bat docker/Dockerfile-0-base -H 3:15

p "# Build the base image"
make build-0-base

pe "clear"

p "# Scan the image"
echo "Scanning base image with Trivy"
sleep 1
echo "Scanned base image with Trivy"
echo ""
echo "Scanning base image with Grype"
sleep 1
echo "Scanned base image with Grype"
echo ""
echo "Scanning base image with Docker Scan"
sleep 1
echo "Scanned base image with Docker Scan"
echo ""
echo "Scanning base image with Docker Scout"
sleep 1
echo "Scanned base image with Docker Scout"

p "# View Results Summary"
clear
make results-0-base-table

p "# end"
clear
