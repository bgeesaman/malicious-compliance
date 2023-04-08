#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Generate SBOMs for 0-base and 5-zero images"
make trivy-0-base-sbom
make trivy-4-zero-sbom
make syft-0-base-sbom
make syft-5-zero-sbom


p "# Scan the 0-base and 5-zero SBOMs with Trivy"
make trivy-0-base-sbom-summary
make trivy-5-zero-sbom-summary

p "# Scan the 0-base and 5-zero SBOMs with Grype"
make grype-0-base-sbom-summary
make grype-5-zero-sbom-summary

p "# View results"
clear
# make results-5-zero-sbom

pe "clear"
