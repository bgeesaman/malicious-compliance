#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""

p "# Show Trivy's original image scan results of the original base image"
# make trivy-results-0-base-summary
echo "Trivy results summary for direct scan of the original base image"
echo "  64 os-pkg"
echo "  18 runtime/language dependency file"
echo "   3 binary"
p "# Now, scan the Trivy-generated SBOMs for the original base and multi-stage built images with Trivy"
# make trivy-0-base-sbom-summary
# make trivy-5-zero-sbom-summary
echo "Trivy results summary for scan of Trivy-generated SBOM of the original base image"
sleep 0.3
echo "  64 os-pkg"
echo "  18 runtime/language dependency file"
echo "   3 binary"
sleep 0.2
echo "Trivy results summary for scan of Trivy-generated SBOM of the multi-stage built image"
sleep 0.3
echo "   0 os-pkg"
echo "   0 runtime/language dependency file"
echo "   0 binary"

pe "clear"

p "# Results of Grype directly scanning the original base image"
# make grype-results-0-base-summary
echo "Grype results summary for direct scan of the original base image"
echo " 159 os-pkg"
echo "  97 runtime/language dependency file"
echo "  54 binary"
p "# Now, scan the Syft-generated SBOM for the original base and multi-stage built images with Grype"
# make grype-0-base-sbom-summary
# make grype-5-zero-sbom-summary
echo "Grype results summary for scan of Syft-generated SBOM of the original base image"
sleep 0.3
echo " 306 os-pkg"
echo "  80 runtime/language dependency file"
echo "  17 binary"
sleep 0.2
echo "Grype results summary for scan of Syft-generated SBOM of the multi-stage built image"
sleep 0.3
echo "   0 os-pkg"
echo "   0 runtime/language dependency file"
echo "   0 binary"

echo ""
p "# end"
clear
