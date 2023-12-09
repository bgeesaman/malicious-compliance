# Malicious Compliance: Reflections on Trusting Container Image Scanners

## KubeCon EU 2023 Amsterdam

- [Talk Recording](https://www.youtube.com/watch?v=9weGi0csBZM&list=PLj6h78yzYM2PyrvCoOii4rAopBswfz1p7&index=212)
- [Slides PDF](https://static.sched.com/hosted_files/kccnceu2023/c1/Malicious%20Compliance.pdf)
- [Talk Abstract and Details](https://sched.co/1Hybu)

## Presenters and Repo Contributors

- [Ian Coldwater](https://twitter.com/IanColdwater)
- [Duffie Cooley](https://twitter.com/mauilion)
- [Brad Geesaman](https://twitter.com/bradgeesaman)
- [Rory McCune](https://twitter.com/raesene)

## Talk References

- [Original base image](https://k8s.rip/mc-base)
- [Exploiting a Slightly Peculiar Volume Configuration with SIG-Honk](https://k8s.rip/spvc)
- [Reflections on Trusting Trust](https://k8s.rip/trust)
- [The best way to write secure and reliable applications!](https://github.com/kelseyhightower/nocode)

## Repo Usage

### Getting Started

If you want to follow along with the things we did in the talk, first, git clone this repo. Next, install the following dependencies/tools.

**Note for M1/Arm users** - This demo should work as-is with one exception, and that is the `kubectl` binary.  Download a `kubectl` binary for `arm64` overtop the current `amd64` binary before building the images.

### Install dependencies

- [Docker](https://www.docker.com/)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Grype](https://github.com/anchore/grype)
- [Syft](https://github.com/anchore/syft)
- [Docker Scan](https://docs.docker.com/engine/scan/)
- [Docker Scout](https://docs.docker.com/scout/)
- [jq](https://stedolan.github.io/jq/)


### Build the images

Run the following command to build all the variations of the images:

```bash
make build-all
```

Scan the base image with all four scanners:

```bash
make scan-0-base
```

Show the results of scanning the base image:

```bash
make results-0-base
```

Repeat these steps for each of the image variants:

- `make scan-1-os` `make results-1-os` - Modified /etc/os-release
- `make scan-2-pkg` `make results-2-pkg`- Deleted APK metadata
- `make scan-3-lang` `make results-3-lang` - Symlinked Language Dependency Files
- `make scan-4-bin` `make results-4-bin`- UPX packed binaries
- `make scan-5-zero` `make results-5-zero`- Multi-stage build with all techniques combined

## Other Exploration

Run `make` and see all the helper commands we used during this research.
