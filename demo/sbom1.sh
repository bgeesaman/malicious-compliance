#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Generate SBOMs for original base and multi-stage built images"
echo "Trivy generate SBOM for original base image"
sleep 1
echo "Trivy generate SBOM for multi-stage built image"
sleep 0.2
echo ""
echo "Syft generate SBOM for original base image"
sleep 1
echo "Syft generate SBOM for multi-stage built image"
sleep 0.2

p "# List our SBOM results"
ls -al results/sbom-*

p "# View Syft SBOM for original base image"
jless results/sbom-syft-0-base.json
p "# View Trivy SBOM for original base image"
jless results/sbom-trivy-scan-0-base.json
p "# View Trivy SBOM for multi-stage built image"
jless results/sbom-trivy-scan-5-zero.json

pe "# end"
clear
