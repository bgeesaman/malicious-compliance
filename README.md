# Malicious Compliance

Usage is to run `make` and view the help output.

There are 6 images to build/run/scan/view results:
- 0-base - the base image
- 1-os - OS detection bypass
- 2-pkg - OS Package metadata removal
- 3-lang - Language runtime dependency symlinking
- 4-bin - Binary metadata stripping
- 5-zero - All techniques combined with a multi-staged build to be a single layer


To build all images: `make build-all`
To scan the 0-base image: `make scan-0-base`
To view the 0-base image scan results: `make results-0-base`
Repeat for `make scan-<N>-<ext>; make results-<N>-<ext>`

To run shell in 3-lang: `make run-3-lang`
To view the 4-bin results: `make grype-scan-4-bin`
