#!/bin/bash

########################
# include the magic
########################
. ./lib/demo-magic.sh
TYPE_SPEED=18
clear

echo ""
p "# Let's view /bin/bash in original base image"
docker run -it --rm sig-honk/malicious-compliance:0-base ls -al /bin/bash

p "# Now, view /bin/bash in the multi-stage built image"
docker run -it --rm sig-honk/malicious-compliance:5-zero ls -al /bin/bash
p "# Show the contents of /bin/bash in the multi-stage built image"
docker run -it --rm sig-honk/malicious-compliance:5-zero cat /bin/bash
echo ""

p "# Is \"eicar\" anywhere in the results?"
pe "grep -i eicar results/*"
echo ""

pe "# end"
clear
