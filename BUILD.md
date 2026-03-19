## Development
```bash
# Run tests
make test

# Lint
make lint

# Build
make build

# Build, test, and lint
make all
```

## Building VM Images Locally
To build VM images locally (requires root on Alpine Linux or a CI environment):

```bash
cd vm
sudo VERSION=v1.0.0 ./build.sh
```

This produces `dist/firewall4ai-v1.0.0.{qcow2,vmdk,vhdx}`.

## Release
Releases are automated via GitHub Actions. To create a release:
```bash
git tag v1.0.0
git push origin v1.0.0
```

This builds a Linux amd64 binary and VM appliance images (qcow2, vmdk, vhdx), then creates a GitHub release with auto-generated release notes.
