# Malicious Compliance

Usage is to run `make` and view the help output.

There are 6 images to build/run/scan/view results:
- 0-base - the base image
- 1-os - OS detection bypass
- 2-pkg - OS Package metadata removal
- 3-lang - Language runtime dependency symlinking
- 4-bin - Binary metadata stripping
- 5-zero - All techniques combined with a multi-staged build to be a single layer
