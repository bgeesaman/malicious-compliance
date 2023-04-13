#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Generate SBOMs for 0-base and 5-zero images"
echo "Trivy 0-base generate sbom"
sleep 1
echo "Trivy 5-zero generate sbom"
sleep 0.2
echo "Syft 0-base generate sbom"
sleep 1
echo "Syft 5-zero generate sbom"
sleep 0.2

p "# Show Trivy's original image scan results of 0-base"
make trivy-results-0-base-summary
p "# Now, scan the 0-base and 5-zero image SBOMs with Trivy"
make trivy-0-base-sbom-summary
make trivy-5-zero-sbom-summary

pe "clear"

p "# Show Grype's original image scan results of 0-base"
make grype-results-0-base-summary
p "# Now, scan the 0-base and 5-zero image SBOMs with Grype"
make grype-0-base-sbom-summary
make grype-5-zero-sbom-summary

p "# List our SBOM results"
ls -al results/sbom-*

p "# View a Syft SBOM for 0-base"
jless results/sbom-syft-0-base.json
p "# View a Trivy SBOM for 0-base"
jless results/sbom-trivy-scan-0-base.json
p "# View a Trivy SBOM for 5-zero"
jless results/sbom-trivy-scan-5-zero.json

pe "clear"

p "# Use docker run to show /bin/bash in 0-base"
docker run -it --rm sig-honk/malicious-compliance:0-base ls -al /bin/bash

p "# Use docker run to show /bin/bash in 5-zero"
docker run -it --rm sig-honk/malicious-compliance:5-zero ls -al /bin/bash
p "# Contents of /bin/bash in 5-zero:"
docker run -it --rm sig-honk/malicious-compliance:5-zero cat /bin/bash
echo ""

p "# Is \"eicar\" anywhere in the results?"
pe "grep -i eicar results/*"
echo ""
