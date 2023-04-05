SHELL := /usr/bin/env bash
DIR := $(notdir $(CURDIR))

IMAGENAME=$(DIR)
IMAGEREPO=sig-honk/$(DIR)
RESULTS_DIR=results

.PHONY: help
help: ## Print help
	@awk 'BEGIN {FS = ": .*##"; printf "\nUsage:  make <command>\nCommands:\n\033[36m\033[0m\n"} /^[$$()% 0-9a-zA-Z_-]+(\\:[$$()% 0-9a-zA-Z_-]+)*:.*?##/ { gsub(/\\:/,":", $$1); printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

build-all: build-0-base build-1-os build-2-pkg build-3-lang build-4-bin build-5-zero ## Build all base images

.PHONY: build-0-base
build-0-base: ## Build the base image
	@echo "Building 0-base"
	@docker build -t $(IMAGEREPO):0-base -f docker/Dockerfile-0-base docker/

.PHONY: build-1-os
build-1-os: ## Build the image without OS detection
	@echo "Building 1-os"
	@docker build -t $(IMAGEREPO):1-os -f docker/Dockerfile-1-os docker/

.PHONY: build-2-pkg
build-2-pkg: ## Build the image without package detection
	@echo "Building 2-pkg"
	@docker build -t $(IMAGEREPO):2-pkg -f docker/Dockerfile-2-pkg docker/

.PHONY: build-3-lang
build-3-lang: ## Build the image without language dependency detection
	@echo "Building 3-lang"
	@docker build -t $(IMAGEREPO):3-lang -f docker/Dockerfile-3-lang docker/

.PHONY: build-4-bin
build-4-bin: ## Build the image without binary metadata detection
	@echo "Building 4-bin"
	@docker build -t $(IMAGEREPO):4-bin -f docker/Dockerfile-4-bin docker/

.PHONY: build-5-zero
build-5-zero: ## Build the image without any detection
	@echo "Building 5-zero"
	@docker build -t $(IMAGEREPO):5-zero -f docker/Dockerfile-5-zero docker/


#########
## 0-base
#########

.PHONY: run-0-base
run-0-base: ## Run shell in 0-base
	@docker run --rm -it $(IMAGEREPO):0-base /bin/bash

scan-0-base: trivy-scan-0-base grype-scan-0-base ## Scan 0-base with all scanners
results-0-base: trivy-results-0-base grype-results-0-base dockerscan-results-0-base dockerscout-results-0-base ## Show 0-base results for all scanners

.PHONY: trivy-scan-0-base
trivy-scan-0-base: ## Trivy scan 0-base
	@echo "Scanning 0-base with Trivy (image)"
	@trivy image $(IMAGEREPO):0-base --format json --output $(RESULTS_DIR)/trivy-scan-0-base.json || echo "trivy scanned"
	@echo "Scanned 0-base with Trivy (image)"

.PHONY: grype-scan-0-base
grype-scan-0-base: ## Grype scan 0-base
	@echo "Scanning 0-base with grype (image)"
	@grype $(IMAGEREPO):0-base -q -o json > $(RESULTS_DIR)/grype-scan-0-base.json || echo "grype scanned"
	@echo "Scanned 0-base with grype (image)"

.PHONY: dockerscan-scan-0-base
dockerscan-scan-0-base: ## Docker scan 0-base
	@echo "Scanning 0-base with docker scan (image)"
	@docker scan $(IMAGEREPO):0-base --json > $(RESULTS_DIR)/docker-scan-0-base.json || echo "docker scan scanned"
	@echo "Scanned 0-base with docker scan (image)"

.PHONY: dockerscout-scan-0-base
dockerscout-scan-0-base: ## Docker scout 0-base
	@echo "Scanning 0-base with docker scout (image)"
	@docker scout cves --format sarif --output $(RESULTS_DIR)/docker-scout-0-base.json $(IMAGEREPO):0-base || echo "docker scout scanned"
	@echo "Scanned 0-base with docker scout (image)"

.PHONY: trivy-results-0-base
trivy-results-0-base: ## View trivy results for 0-base in JSON
	@echo "Trivy results from scanning 0-base (image)"
	@cat $(RESULTS_DIR)/trivy-scan-0-base.json | jq -rc 'select(.Results != null) | .Results[] | .Target as $$Target | .Type as $$Type | select(.Vulnerabilities != null) | . | .Vulnerabilities[] | ["trivy", $$Target, $$Type, .PkgName, (.Severity| ascii_downcase), .PkgName, .VulnerabilityID]'

.PHONY: trivy-results-0-base-summary
trivy-results-0-base-summary: ## View trivy summary results for 0-base
	@echo "Trivy results summary 0-base (image)"
	@cat $(RESULTS_DIR)/trivy-scan-0-base.json | jq -rc 'select(.Results != null) | .Results[] | .Type as $$Type | select(.Vulnerabilities != null) | .Vulnerabilities[] | "\($$Type)"' | sed -e 's/alpine/os-pkg/g' | sed -e 's/composer/runtime/g' | sed -e 's/cargo/runtime/g' | sed -e 's/gobinary/binary/g' | uniq -c

.PHONY: grype-results-0-base
grype-results-0-base: ## View grype results for 0-base in JSON
	@echo "Grype results from scanning 0-base (image)"
	@cat $(RESULTS_DIR)/grype-scan-0-base.json | jq -rc '.matches[] | ["grype", .vulnerability.namespace, .artifact.type, .artifact.name, (.vulnerability.severity | ascii_downcase), .artifact.version, .vulnerability.id ]'

.PHONY: grype-results-0-base-summary
grype-results-0-base-summary: ## View grype summary results for 0-base
	@echo "Grype results summary 0-base (image)"
	@cat $(RESULTS_DIR)/grype-scan-0-base.json | jq -rc '.matches[] | .artifact | .type' | sort | uniq -c | sed -e 's/apk/os-pkg/g' | sed -e 's/python/binary/g'

.PHONY: dockerscan-results-0-base
dockerscan-results-0-base: ## View Docker scan results for 0-base in JSON
	@echo "Docker Scan results from scanning 0-base (image)"
	@cat $(RESULTS_DIR)/docker-scan-0-base.json | jq -rc '.[].vulnerabilities[] | ["docker-scan", .packageManager,.language,.packageName,.nvdSeverity,.version,.identifiers.CVE[0]]'

.PHONY: dockerscan-results-0-base-summary
dockerscan-results-0-base-summary: ## View Docker scan summary results for 0-base
	@echo "Docker Scan results summary 0-base (image)"
	@cat $(RESULTS_DIR)/docker-scan-0-base.json | jq -rc '.[].vulnerabilities[] | .language' | sed -e 's/linux/os-pkg/g' | sed -e 's/golang/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: dockerscout-results-0-base
dockerscout-results-0-base: ## View Docker scout results for 0-base in JSON
	@echo "Docker Scout results from scanning 0-base (image)"
	@cat $(RESULTS_DIR)/docker-scout-0-base.json | jq -rc '.runs[].tool.driver as $$driver | .runs[].results[] | [$$driver.fullName, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].name, (.ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.cvssV3_severity), .ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.affected_version, $$rule]'

.PHONY: dockerscout-results-0-base-summary
dockerscout-results-0-base-summary: ## View Docker scout summary results for 0-base 
	@echo "Docker Scout results summary 0-base (image)"
	@cat $(RESULTS_DIR)/docker-scout-0-base.json | jq -rc '.runs[].results[] | .locations[].logicalLocations[0].kind' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/golang/binary/g' | sed -e 's/pypi/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: results-0-base-summary
results-0-base-summary: trivy-results-0-base-summary grype-results-0-base-summary dockerscan-results-0-base-summary dockerscout-results-0-base-summary ## View all results, summarized

#######
## 1-os
#######

.PHONY: run-1-os
run-1-os: ## Run shell in 1-os
	@docker run --rm -it $(IMAGEREPO):1-os /bin/bash

scan-1-os: trivy-scan-1-os grype-scan-1-os ## Scan 1-os with all scanners
results-1-os: trivy-results-1-os grype-results-1-os dockerscan-results-1-os dockerscout-results-1-os ## Show 1-os results for all scanners

.PHONY: trivy-scan-1-os
trivy-scan-1-os: ## Trivy scan 1-os
	@echo "Scanning 1-os with Trivy (image)"
	@trivy image $(IMAGEREPO):1-os --format json --output $(RESULTS_DIR)/trivy-scan-1-os.json || echo "trivy scanned"
	@echo "Scanned 1-os with Trivy (image)"

.PHONY: grype-scan-1-os
grype-scan-1-os: ## Grype scan 1-os
	@echo "Scanning 1-os with grype (image)"
	@grype $(IMAGEREPO):1-os -q -o json > $(RESULTS_DIR)/grype-scan-1-os.json || echo "grype scanned"
	@echo "Scanned 1-os with grype (image)"

.PHONY: dockerscan-scan-1-os
dockerscan-scan-1-os: ## Docker scan 1-os
	@echo "Scanning 1-os with docker scan (image)"
	@docker scan $(IMAGEREPO):1-os --json > $(RESULTS_DIR)/docker-scan-1-os.json || echo "docker scan scanned"
	@echo "Scanned 1-os with docker scan (image)"

.PHONY: dockerscout-scan-1-os
dockerscout-scan-1-os: ## Docker scout 1-os
	@echo "Scanning 1-os with docker scout (image)"
	@docker scout cves --format sarif --output $(RESULTS_DIR)/docker-scout-1-os.json $(IMAGEREPO):1-os || echo "docker scout scanned"
	@echo "Scanned 1-os with docker scout (image)"

.PHONY: trivy-results-1-os
trivy-results-1-os: ## View trivy results for 1-os in JSON
	@echo "Trivy results from scanning 1-os (image)"
	@cat $(RESULTS_DIR)/trivy-scan-1-os.json | jq -rc 'select(.Results != null) | .Results[] | .Target as $$Target | .Type as $$Type | select(.Vulnerabilities != null) | . | .Vulnerabilities[] | ["trivy", $$Target, $$Type, .PkgName, (.Severity| ascii_downcase), .PkgName, .VulnerabilityID]'

.PHONY: trivy-results-1-os-summary
trivy-results-1-os-summary: ## View trivy summary results for 1-os
	@echo "Trivy results summary 1-os (image)"
	@cat $(RESULTS_DIR)/trivy-scan-1-os.json | jq -rc 'select(.Results != null) | .Results[] | .Type as $$Type | select(.Vulnerabilities != null) | .Vulnerabilities[] | "\($$Type)"' | sed -e 's/alpine/os-pkg/g' | sed -e 's/composer/runtime/g' | sed -e 's/cargo/runtime/g' | sed -e 's/gobinary/binary/g' | uniq -c

.PHONY: grype-results-1-os
grype-results-1-os: ## View grype results for 1-os in JSON
	@echo "Grype results from scanning 1-os (image)"
	@cat $(RESULTS_DIR)/grype-scan-1-os.json | jq -rc '.matches[] | ["grype", .vulnerability.namespace, .artifact.type, .artifact.name, (.vulnerability.severity | ascii_downcase), .artifact.version, .vulnerability.id ]'

.PHONY: grype-results-1-os-summary
grype-results-1-os-summary: ## View grype summary results for 1-os
	@echo "Grype results summary 1-os (image)"
	@cat $(RESULTS_DIR)/grype-scan-1-os.json | jq -rc '.matches[] | .artifact | .type' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/python/binary/g' | sed -e 's/go-module/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: dockerscan-results-1-os
dockerscan-results-1-os: ## View Docker scan results for 1-os in JSON
	@echo "Docker Scan results from scanning 1-os (image)"
	@cat $(RESULTS_DIR)/docker-scan-1-os.json | jq -rc '.[].vulnerabilities[] | ["docker-scan", .packageManager,.language,.packageName,.nvdSeverity,.version,.identifiers.CVE[0]]'

.PHONY: dockerscan-results-1-os-summary
dockerscan-results-1-os-summary: ## View Docker scan summary results for 1-os
	@echo "Docker Scan results summary 1-os (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/docker-scan-1-os.json | jq -rc '.[].vulnerabilities[] | .language' | sed -e 's/linux/os-pkg/g' | sed -e 's/golang/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: dockerscout-results-1-os
dockerscout-results-1-os: ## View Docker scout results for 1-os in JSON
	@echo "Docker Scout results from scanning 1-os (image)"
	@cat $(RESULTS_DIR)/docker-scout-1-os.json | jq -rc '.runs[].tool.driver as $$driver | .runs[].results[] | [$$driver.fullName, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].name, (.ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.cvssV3_severity), .ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.affected_version, $$rule]'

.PHONY: dockerscout-results-1-os-summary
dockerscout-results-1-os-summary: ## View Docker scout summary results for 1-os
	@echo "Docker Scout results summary 1-os (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/docker-scout-1-os.json | jq -rc '.runs[].results[] | .locations[].logicalLocations[0].kind' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/golang/binary/g' | sed -e 's/pypi/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: results-1-os-summary
results-1-os-summary: trivy-results-1-os-summary grype-results-1-os-summary dockerscan-results-1-os-summary dockerscout-results-1-os-summary ## View all results, summarized

#######
## 2-pkg
#######

.PHONY: run-2-pkg
run-2-pkg: ## Run shell in 2-pkg
	@docker run --rm -it $(IMAGEREPO):2-pkg /bin/bash

scan-2-pkg: trivy-scan-2-pkg grype-scan-2-pkg ## Scan 2-pkg with all scanners
results-2-pkg: trivy-results-2-pkg grype-results-2-pkg dockerscan-results-2-pkg dockerscout-results-2-pkg ## Show 2-pkg results for all scanners

.PHONY: trivy-scan-2-pkg
trivy-scan-2-pkg: ## Trivy scan 2-pkg
	@echo "Scanning 2-pkg with Trivy (image)"
	@trivy image $(IMAGEREPO):2-pkg --format json --output $(RESULTS_DIR)/trivy-scan-2-pkg.json || echo "trivy scanned"
	@echo "Scanned 2-pkg with Trivy (image)"

.PHONY: grype-scan-2-pkg
grype-scan-2-pkg: ## Grype scan 2-pkg
	@echo "Scanning 2-pkg with grype (image)"
	@grype $(IMAGEREPO):2-pkg -q -o json > $(RESULTS_DIR)/grype-scan-2-pkg.json || echo "grype scanned"
	@echo "Scanned 2-pkg with grype (image)"

.PHONY: dockerscan-scan-2-pkg
dockerscan-scan-2-pkg: ## Docker scan 2-pkg
	@echo "Scanning 2-pkg with docker scan (image)"
	@docker scan $(IMAGEREPO):2-pkg --json > $(RESULTS_DIR)/docker-scan-2-pkg.json || echo "docker scan scanned"
	@echo "Scanned 2-pkg with docker scan (image)"

.PHONY: dockerscout-scan-2-pkg
dockerscout-scan-2-pkg: ## Docker scout 2-pkg
	@echo "Scanning 2-pkg with docker scout (image)"
	@docker scout cves --format sarif --output $(RESULTS_DIR)/docker-scout-2-pkg.json $(IMAGEREPO):2-pkg || echo "docker scout scanned"
	@echo "Scanned 2-pkg with docker scout (image)"

.PHONY: trivy-results-2-pkg
trivy-results-2-pkg: ## View trivy results for 2-pkg in JSON
	@echo "Trivy results from scanning 2-pkg (image)"
	@cat $(RESULTS_DIR)/trivy-scan-2-pkg.json | jq -rc 'select(.Results != null) | .Results[] | .Target as $$Target | .Type as $$Type | select(.Vulnerabilities != null) | . | .Vulnerabilities[] | ["trivy", $$Target, $$Type, .PkgName, (.Severity| ascii_downcase), .PkgName, .VulnerabilityID]'

.PHONY: trivy-results-2-pkg-summary
trivy-results-2-pkg-summary: ## View trivy summary results for 2-pkg
	@echo "Trivy results summary 2-pkg (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/trivy-scan-2-pkg.json | jq -rc 'select(.Results != null) | .Results[] | .Type as $$Type | select(.Vulnerabilities != null) | .Vulnerabilities[] | "\($$Type)"' | sed -e 's/alpine/os-pkg/g' | sed -e 's/composer/runtime/g' | sed -e 's/cargo/runtime/g' | sed -e 's/gobinary/binary/g' | uniq -c

.PHONY: grype-results-2-pkg
grype-results-2-pkg: ## View grype results for 2-pkg in JSON
	@echo "Grype results from scanning 2-pkg (image)"
	@cat $(RESULTS_DIR)/grype-scan-2-pkg.json | jq -rc '.matches[] | ["grype", .vulnerability.namespace, .artifact.type, .artifact.name, (.vulnerability.severity | ascii_downcase), .artifact.version, .vulnerability.id ]'

.PHONY: grype-results-2-pkg-summary
grype-results-2-pkg-summary: ## View grype summary results for 2-pkg
	@echo "Grype results summary 2-pkg (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/grype-scan-2-pkg.json | jq -rc '.matches[] | .artifact | .type' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/python/binary/g' | sed -e 's/go-module/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: dockerscan-results-2-pkg
dockerscan-results-2-pkg: ## View Docker scan results for 2-pkg in JSON
	@echo "Docker Scan results from scanning 2-pkg (image)"
	@cat $(RESULTS_DIR)/docker-scan-2-pkg.json | jq -rc '.[].vulnerabilities[] | ["docker-scan", .packageManager,.language,.packageName,.nvdSeverity,.version,.identifiers.CVE[0]]'

.PHONY: dockerscan-results-2-pkg-summary
dockerscan-results-2-pkg-summary: ## View Docker scan summary results for 2-pkg
	@echo "Docker Scan results summary 2-pkg (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/docker-scan-2-pkg.json | jq -rc '.[].vulnerabilities[] | .language' | sed -e 's/linux/os-pkg/g' | sed -e 's/golang/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: dockerscout-results-2-pkg
dockerscout-results-2-pkg: ## View Docker scout results for 2-pkg in JSON
	@echo "Docker Scout results from scanning 2-pkg (image)"
	@cat $(RESULTS_DIR)/docker-scout-2-pkg.json | jq -rc '.runs[].tool.driver as $$driver | .runs[].results[] | [$$driver.fullName, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].name, (.ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.cvssV3_severity), .ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.affected_version, $$rule]'

.PHONY: dockerscout-results-2-pkg-summary
dockerscout-results-2-pkg-summary: ## View Docker scout summary results for 2-pkg
	@echo "Docker Scout results summary 2-pkg (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/docker-scout-2-pkg.json | jq -rc '.runs[].results[] | .locations[].logicalLocations[0].kind' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/golang/binary/g' | sed -e 's/pypi/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: results-2-pkg-summary
results-2-pkg-summary: trivy-results-2-pkg-summary grype-results-2-pkg-summary dockerscan-results-2-pkg-summary dockerscout-results-2-pkg-summary ## View all results, summarized


#######
## 3-lang
#######

.PHONY: run-3-lang
run-3-lang: ## Run shell in 3-lang
	@docker run --rm -it $(IMAGEREPO):3-lang /bin/bash

scan-3-lang: trivy-scan-3-lang grype-scan-3-lang ## Scan 3-lang with all scanners
results-3-lang: trivy-results-3-lang grype-results-3-lang dockerscan-results-3-lang dockerscout-results-3-lang ## Show 3-lang results for all scanners

.PHONY: trivy-scan-3-lang
trivy-scan-3-lang: ## Trivy scan 3-lang
	@echo "Scanning 3-lang with Trivy (image)"
	@trivy image $(IMAGEREPO):3-lang --format json --output $(RESULTS_DIR)/trivy-scan-3-lang.json || echo "trivy scanned"
	@echo "Scanned 3-lang with Trivy (image)"

.PHONY: grype-scan-3-lang
grype-scan-3-lang: ## Grype scan 3-lang
	@echo "Scanning 3-lang with grype (image)"
	@grype $(IMAGEREPO):3-lang -q -o json > $(RESULTS_DIR)/grype-scan-3-lang.json || echo "grype scanned"
	@echo "Scanned 3-lang with grype (image)"

.PHONY: dockerscan-scan-3-lang
dockerscan-scan-3-lang: ## Docker scan 3-lang
	@echo "Scanning 3-lang with docker scan (image)"
	@docker scan $(IMAGEREPO):3-lang --json > $(RESULTS_DIR)/docker-scan-3-lang.json || echo "docker scan scanned"
	@echo "Scanned 3-lang with docker scan (image)"

.PHONY: dockerscout-scan-3-lang
dockerscout-scan-3-lang: ## Docker scout 3-lang
	@echo "Scanning 3-lang with docker scout (image)"
	@docker scout cves --format sarif --output $(RESULTS_DIR)/docker-scout-3-lang.json $(IMAGEREPO):3-lang || echo "docker scout scanned"
	@echo "Scanned 3-lang with docker scout (image)"

.PHONY: trivy-results-3-lang
trivy-results-3-lang: ## View trivy results for 3-lang in JSON
	@echo "Trivy results from scanning 3-lang (image)"
	@cat $(RESULTS_DIR)/trivy-scan-3-lang.json | jq -rc 'select(.Results != null) | .Results[] | .Target as $$Target | .Type as $$Type | select(.Vulnerabilities != null) | . | .Vulnerabilities[] | ["trivy", $$Target, $$Type, .PkgName, (.Severity| ascii_downcase), .PkgName, .VulnerabilityID]'

.PHONY: trivy-results-3-lang-summary
trivy-results-3-lang-summary: ## View trivy summary results for 3-lang
	@echo "Trivy results summary 3-lang (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/trivy-scan-3-lang.json | jq -rc 'select(.Results != null) | .Results[] | .Type as $$Type | select(.Vulnerabilities != null) | .Vulnerabilities[] | "\($$Type)"' | sed -e 's/alpine/os-pkg/g' | sed -e 's/composer/runtime/g' | sed -e 's/cargo/runtime/g' | sed -e 's/gobinary/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: grype-results-3-lang
grype-results-3-lang: ## View grype results for 3-lang in JSON
	@echo "Grype results from scanning 3-lang (image)"
	@cat $(RESULTS_DIR)/grype-scan-3-lang.json | jq -rc '.matches[] | ["grype", .vulnerability.namespace, .artifact.type, .artifact.name, (.vulnerability.severity | ascii_downcase), .artifact.version, .vulnerability.id ]'

.PHONY: grype-results-3-lang-summary
grype-results-3-lang-summary: ## View grype summary results for 3-lang
	@echo "Grype results summary 3-lang (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/grype-scan-3-lang.json | jq -rc '.matches[] | .artifact | .type' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/python/binary/g' | sed -e 's/go-module/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: dockerscan-results-3-lang
dockerscan-results-3-lang: ## View Docker scan results for 3-lang in JSON
	@echo "Docker Scan results from scanning 3-lang (image)"
	@cat $(RESULTS_DIR)/docker-scan-3-lang.json | jq -rc '.[].vulnerabilities[] | ["docker-scan", .packageManager,.language,.packageName,.nvdSeverity,.version,.identifiers.CVE[0]]'

.PHONY: dockerscan-results-3-lang-summary
dockerscan-results-3-lang-summary: ## View Docker scan summary results for 3-lang
	@echo "Docker Scan results summary 3-lang (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/docker-scan-3-lang.json | jq -rc '.[].vulnerabilities[] | .language' | sed -e 's/linux/os-pkg/g' | sed -e 's/golang/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: dockerscout-results-3-lang
dockerscout-results-3-lang: ## View Docker scout results for 3-lang in JSON
	@echo "Docker Scout results from scanning 3-lang (image)"
	@cat $(RESULTS_DIR)/docker-scout-3-lang.json | jq -rc '.runs[].tool.driver as $$driver | .runs[].results[] | [$$driver.fullName, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].name, (.ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.cvssV3_severity), .ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.affected_version, $$rule]'

.PHONY: dockerscout-results-3-lang-summary
dockerscout-results-3-lang-summary: ## View Docker scout summary results for 3-lang
	@echo "Docker Scout results summary 3-lang (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/docker-scout-3-lang.json | jq -rc '.runs[].results[] | .locations[].logicalLocations[0].kind' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/golang/binary/g' | sed -e 's/pypi/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: results-3-lang-summary
results-3-lang-summary: trivy-results-3-lang-summary grype-results-3-lang-summary dockerscan-results-3-lang-summary dockerscout-results-3-lang-summary ## View all results, summarized


#######
## 4-bin
#######

.PHONY: run-4-bin
run-4-bin: ## Run shell in 4-bin
	@docker run --rm -it $(IMAGEREPO):4-bin /bin/bash

scan-4-bin: trivy-scan-4-bin grype-scan-4-bin ## Scan 4-bin with all scanners
results-4-bin: trivy-results-4-bin grype-results-4-bin dockerscan-results-4-bin dockerscout-results-4-bin ## Show 4-bin results for all scanners

.PHONY: trivy-scan-4-bin
trivy-scan-4-bin: ## Trivy scan 4-bin
	@echo "Scanning 4-bin with Trivy (image)"
	@trivy image $(IMAGEREPO):4-bin --format json --output $(RESULTS_DIR)/trivy-scan-4-bin.json || echo "trivy scanned"
	@echo "Scanned 4-bin with Trivy (image)"

.PHONY: grype-scan-4-bin
grype-scan-4-bin: ## Grype scan 4-bin
	@echo "Scanning 4-bin with grype (image)"
	@grype $(IMAGEREPO):4-bin -q -o json > $(RESULTS_DIR)/grype-scan-4-bin.json || echo "grype scanned"
	@echo "Scanned 4-bin with grype (image)"

.PHONY: dockerscan-scan-4-bin
dockerscan-scan-4-bin: ## Docker scan 4-bin
	@echo "Scanning 4-bin with docker scan (image)"
	@docker scan $(IMAGEREPO):4-bin --json > $(RESULTS_DIR)/docker-scan-4-bin.json || echo "docker scan scanned"
	@echo "Scanned 4-bin with docker scan (image)"

.PHONY: dockerscout-scan-4-bin
dockerscout-scan-4-bin: ## Docker scout 4-bin
	@echo "Scanning 4-bin with docker scout (image)"
	@docker scout cves --format sarif --output $(RESULTS_DIR)/docker-scout-4-bin.json $(IMAGEREPO):4-bin || echo "docker scout scanned"
	@echo "Scanned 4-bin with docker scout (image)"

.PHONY: trivy-results-4-bin
trivy-results-4-bin: ## View trivy results for 4-bin in JSON
	@echo "Trivy results from scanning 4-bin (image)"
	@cat $(RESULTS_DIR)/trivy-scan-4-bin.json | jq -rc 'select(.Results != null) | .Results[] | .Target as $$Target | .Type as $$Type | select(.Vulnerabilities != null) | . | .Vulnerabilities[] | ["trivy", $$Target, $$Type, .PkgName, (.Severity| ascii_downcase), .PkgName, .VulnerabilityID]'

.PHONY: trivy-results-4-bin-summary
trivy-results-4-bin-summary: ## View trivy summary results for 4-bin
	@echo "Trivy results summary 4-bin (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/trivy-scan-4-bin.json | jq -rc 'select(.Results != null) | .Results[] | .Type as $$Type | select(.Vulnerabilities != null) | .Vulnerabilities[] | "\($$Type)"' | sed -e 's/alpine/os-pkg/g' | sed -e 's/composer/runtime/g' | sed -e 's/cargo/runtime/g' | sed -e 's/gobinary/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: grype-results-4-bin
grype-results-4-bin: ## View grype results for 4-bin in JSON
	@echo "Grype results from scanning 4-bin (image)"
	@cat $(RESULTS_DIR)/grype-scan-4-bin.json | jq -rc '.matches[] | ["grype", .vulnerability.namespace, .artifact.type, .artifact.name, (.vulnerability.severity | ascii_downcase), .artifact.version, .vulnerability.id ]'

.PHONY: grype-results-4-bin-summary
grype-results-4-bin-summary: ## View grype summary results for 4-bin
	@echo "Grype results summary 4-bin (image)"
	@cat $(RESULTS_DIR)/grype-scan-4-bin.json | jq -rc '.matches[] | .artifact | .type' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/python/binary/g' | sed -e 's/go-module/binary/g' | uniq -c && echo "   0 os-pkg" && echo "   0 binary" && echo "   0 runtime"

.PHONY: dockerscan-results-4-bin
dockerscan-results-4-bin: ## View Docker scan results for 4-bin in JSON
	@echo "Docker Scan results from scanning 4-bin (image)"
	@cat $(RESULTS_DIR)/docker-scan-4-bin.json | jq -rc '.[].vulnerabilities[] | ["docker-scan", .packageManager,.language,.packageName,.nvdSeverity,.version,.identifiers.CVE[0]]'

.PHONY: dockerscan-results-4-bin-summary
dockerscan-results-4-bin-summary: ## View Docker scan summary results for 4-bin
	@echo "Docker Scan results summary 4-bin (image)"
	@echo "   0 os-pkg" && cat $(RESULTS_DIR)/docker-scan-4-bin.json | jq -rc '.[].vulnerabilities[] | .language' | sed -e 's/linux/os-pkg/g' | sed -e 's/golang/binary/g' | uniq -c && echo "   0 runtime"

.PHONY: dockerscout-results-4-bin
dockerscout-results-4-bin: ## View Docker scout results for 4-bin in JSON
	@echo "Docker Scout results from scanning 4-bin (image)"
	@cat $(RESULTS_DIR)/docker-scout-4-bin.json | jq -rc '.runs[].tool.driver as $$driver | .runs[].results[] | [$$driver.fullName, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].name, (.ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.cvssV3_severity), .ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.affected_version, $$rule]'

.PHONY: dockerscout-results-4-bin-summary
dockerscout-results-4-bin-summary: ## View Docker scout summary results for 3-lang
	@echo "Docker Scout results summary 4-bin (image)"
	@cat $(RESULTS_DIR)/docker-scout-4-bin.json | jq -rc '.runs[].results[] | .locations[].logicalLocations[0].kind' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/golang/binary/g' | sed -e 's/pypi/binary/g' | uniq -c && echo "   0 os-pkg" && echo "   0 binary" && echo "   0 runtime"

.PHONY: results-4-bin-summary
results-4-bin-summary: trivy-results-4-bin-summary grype-results-4-bin-summary dockerscan-results-4-bin-summary dockerscout-results-4-bin-summary ## View all results, summarized


#######
## 5-zero
#######

.PHONY: run-5-zero
run-5-zero: ## Run shell in 5-zero
	@docker run --rm -it $(IMAGEREPO):5-zero /bin/bash

scan-5-zero: trivy-scan-5-zero grype-scan-5-zero ## Scan 5-zero with all scanners
results-5-zero: trivy-results-5-zero grype-results-5-zero dockerscan-results-5-zero dockerscout-results-5-zero ## Show 5-zero results for all scanners

.PHONY: trivy-scan-5-zero
trivy-scan-5-zero: ## Trivy scan 5-zero
	@echo "Scanning 5-zero with Trivy (image)"
	@trivy image $(IMAGEREPO):5-zero --format json --output $(RESULTS_DIR)/trivy-scan-5-zero.json || echo "trivy scanned"
	@echo "Scanned 5-zero with Trivy (image)"

.PHONY: grype-scan-5-zero
grype-scan-5-zero: ## Grype scan 5-zero
	@echo "Scanning 5-zero with grype (image)"
	@grype $(IMAGEREPO):5-zero -q -o json > $(RESULTS_DIR)/grype-scan-5-zero.json || echo "grype scanned"
	@echo "Scanned 5-zero with grype (image)"

.PHONY: dockerscan-scan-5-zero
dockerscan-scan-5-zero: ## Docker scan 5-zero
	@echo "Scanning 5-zero with docker scan (image)"
	@docker scan $(IMAGEREPO):5-zero --json > $(RESULTS_DIR)/docker-scan-5-zero.json || echo "docker scan scanned"
	@echo "Scanned 5-zero with docker scan (image)"

.PHONY: dockerscout-scan-5-zero
dockerscout-scan-5-zero: ## Docker scout 5-zero
	@echo "Scanning 5-zero with docker scout (image)"
	@docker scout cves --format sarif --output $(RESULTS_DIR)/docker-scout-5-zero.json $(IMAGEREPO):5-zero || echo "docker scout scanned"
	@echo "Scanned 5-zero with docker scout (image)"

.PHONY: trivy-results-5-zero
trivy-results-5-zero: ## View trivy results for 5-zero in JSON
	@echo "Trivy results from scanning 5-zero (image)"
	@cat $(RESULTS_DIR)/trivy-scan-5-zero.json | jq -rc 'select(.Results != null) | .Results[] | .Target as $$Target | .Type as $$Type | select(.Vulnerabilities != null) | . | .Vulnerabilities[] | ["trivy", $$Target, $$Type, .PkgName, (.Severity| ascii_downcase), .PkgName, .VulnerabilityID]'

.PHONY: trivy-results-5-zero-summary
trivy-results-5-zero-summary: ## View trivy summary results for 5-zero
	@echo "Trivy results summary 5-zero (image)"
	@cat $(RESULTS_DIR)/trivy-scan-5-zero.json | jq -rc 'select(.Results != null) | .Results[] | .Type as $$Type | select(.Vulnerabilities != null) | .Vulnerabilities[] | "\($$Type)"' | sed -e 's/alpine/os-pkg/g' | sed -e 's/composer/runtime/g' | sed -e 's/cargo/runtime/g' | sed -e 's/gobinary/binary/g' | uniq -c && echo "   0 os-pkg" && echo "   0 binary" && echo "   0 runtime"

.PHONY: grype-results-5-zero
grype-results-5-zero: ## View grype results for 5-zero in JSON
	@echo "Grype results from scanning 5-zero (image)"
	@cat $(RESULTS_DIR)/grype-scan-5-zero.json | jq -rc '.matches[] | ["grype", .vulnerability.namespace, .artifact.type, .artifact.name, (.vulnerability.severity | ascii_downcase), .artifact.version, .vulnerability.id ]'

.PHONY: grype-results-5-zero-summary
grype-results-5-zero-summary: ## View grype summary results for 4-bin
	@echo "Grype results summary 5-zero (image)"
	@cat $(RESULTS_DIR)/grype-scan-5-zero.json | jq -rc '.matches[] | .artifact | .type' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/python/binary/g' | sed -e 's/go-module/binary/g' | uniq -c && echo "   0 os-pkg" && echo "   0 binary" && echo "   0 runtime"

.PHONY: dockerscan-results-5-zero
dockerscan-results-5-zero: ## View Docker scan results for 5-zero in JSON
	@echo "Docker Scan results from scanning 5-zero (image)"
	@cat $(RESULTS_DIR)/docker-scan-5-zero.json | jq -rc 'select(.[].vulnerabilities? != null) | .[] | ["docker-scan", .packageManager,.language,.packageName,.nvdSeverity,.version,.identifiers.CVE[0]]'

.PHONY: dockerscan-results-5-zero-summary
dockerscan-results-5-zero-summary: ## View Docker scan summary results for 5-zero
	@echo "Docker Scan results summary 5-zero (image)"
	@cat $(RESULTS_DIR)/docker-scan-5-zero.json | jq -rc 'select(.[].vulnerabilities? != null) | .[].vulnerabilities[] | .language' | sed -e 's/linux/os-pkg/g' | sed -e 's/golang/binary/g' | uniq -c && echo "   0 os-pkg" && echo "   0 binary" && echo "   0 runtime"

.PHONY: dockerscout-results-5-zero
dockerscout-results-5-zero: ## View Docker scout results for 5-zero in JSON
	@echo "Docker Scout results from scanning 5-zero (image)"
	@cat $(RESULTS_DIR)/docker-scout-5-zero.json | jq -rc '.runs[].tool.driver as $$driver | .runs[].results[] | [$$driver.fullName, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].kind, .locations[].logicalLocations[0].name, (.ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.cvssV3_severity), .ruleId as $$rule | $$driver.rules[] | select(.id == $$rule) | .properties.affected_version, $$rule]'

.PHONY: dockerscout-results-5-zero-summary
dockerscout-results-5-zero-summary: ## View Docker scout summary results for 5-zero
	@echo "Docker Scout results summary 5-zero (image)"
	@cat $(RESULTS_DIR)/docker-scout-5-zero.json | jq -rc '.runs[].results[] | .locations[].logicalLocations[0].kind' | sort | sed -e 's/apk/os-pkg/g' | sed -e 's/golang/binary/g' | sed -e 's/pypi/binary/g' | uniq -c && echo "   0 os-pkg" && echo "   0 binary" && echo "   0 runtime"

.PHONY: results-5-zero-summary
results-5-zero-summary: trivy-results-5-zero-summary grype-results-5-zero-summary dockerscan-results-5-zero-summary dockerscout-results-5-zero-summary ## View all results, summarized


.PHONY: results-summaries
results-summaries: results-0-base-summary results-1-os-summary results-2-pkg-summary results-3-lang-summary results-4-bin-summary results-5-zero-summary
