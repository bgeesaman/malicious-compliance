#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Our Dockerfile with deleted Alpine OS package metadata"

echo "cat Dockerfile-2-pkg" 
bat docker/Dockerfile-2-pkg -H 23:24

p "# Build the modified image"
make build-2-pkg

pe "clear"
p "# Scan the image"
echo "Scanning 2-pkg with Trivy"
sleep 1
echo "Scanned 2-pkg with Trivy"
echo ""
echo "Scanning 2-pkg with Grype"
sleep 1
echo "Scanned 2-pkg with Grype"
echo ""
echo "Scanning 2-pkg with Docker Scan"
sleep 1
echo "Scanned 2-pkg with Docker Scan"
echo ""
echo "Scanning 2-pkg with Docker Scout"
sleep 1
echo "Scanned 2-pkg with Docker Scout"

p "# View results"
clear
make results-2-pkg-table

pe "# end"
clear
