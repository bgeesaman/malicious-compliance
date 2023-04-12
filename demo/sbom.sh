#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Generate SBOMs for 0-base and 6-sbom images"
echo "Trivy 0-base generate sbom"
sleep 1
echo "Trivy 6-sbom generate sbom"
sleep 0.2
echo "Syft 0-base generate sbom"
sleep 1
echo "Syft 6-sbom generate sbom"
sleep 0.2

p "# Scan the 0-base and 6-sbom SBOMs with Trivy"
make trivy-0-base-sbom-summary
make trivy-6-sbom-sbom-summary

p "# Scan the 0-base and 6-sbom SBOMs with Grype"
make grype-0-base-sbom-summary
make grype-6-sbom-sbom-summary

p "# List our SBOM results"
ls -al results/sbom-*

p "# View a Syft SBOM for 0-base"
jless results/sbom-syft-0-base.json
p "# View a Trivy SBOM for 0-base"
jless results/sbom-trivy-scan-0-base.json
p "# View a Trivy SBOM for 6-sbom"
jless results/sbom-trivy-scan-6-sbom.json

p "# Is \"eicar\" anywhere in the results?"
pe "grep eicar results/*"

p ""
