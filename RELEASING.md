# Releasing

A release is a `vX.Y.Z` tag on a commit on `main`. Pushing the tag starts
`.github/workflows/release.yml`, which:

1. runs the CI workflow;
2. builds `receipts-log` for Linux and macOS (amd64 and arm64) as
   reproducible `.tar.gz` archives, with a `SHA256SUMS` file, and records a
   signed build-provenance attestation for every archive;
3. waits for a maintainer to approve the `release` environment, then builds
   the `linux/amd64` and `linux/arm64` image, pushes it to
   `ghcr.io/christiaan839-beep/receipts-log` with an SBOM and provenance,
   and attests the image digest;
4. creates the GitHub release with the archives, `SHA256SUMS` and the
   attestation bundle (`attestation.sigstore.json`).

## A release

```
git tag -s v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

Then approve the `release` deployment in the Actions run.

## Checking a release

```
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify receipts-log_0.1.0_linux_amd64.tar.gz --repo christiaan839-beep/receipts-log
gh attestation verify oci://ghcr.io/christiaan839-beep/receipts-log:0.1.0 --repo christiaan839-beep/receipts-log
```

## One-time setup

After the first image is pushed, open the package on GitHub (your profile →
Packages → receipts-log → Package settings) and set its visibility to
public, so anyone can pull it.
