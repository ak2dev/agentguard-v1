# Security policy

## Reporting a vulnerability

Please report vulnerabilities in Agent Guard privately through GitHub security advisories on this repository ("Report a vulnerability"). Do not open a public issue for vulnerabilities in the scanner itself.

We aim to acknowledge reports within 3 working days and to publish a fix and advisory within 90 days. Reporters who want credit are credited.

In scope, for example:

- any way for scanned content to execute code, read files outside the scan root, or make network requests when no network flag was given;
- secrets from scanned content appearing unredacted in any output format;
- output injection (terminal escape sequences, Markdown, HTML, SARIF) from scanned content;
- SSRF or credential exposure in the opt-in network features;
- bypasses of the rule-pack or IOC-feed signature checks, or of rollback protection.

Detection bypasses (a malicious sample Agent Guard misses) are welcome as ordinary issues with an **inert** reproduction: reserved domains such as `example.invalid`, no working payloads, no live malware.

## Supported versions

Only the latest release receives security fixes during 0.x.

## Verifying releases

Releases are built in GitHub Actions and signed with Sigstore (keyless). Each release includes a CycloneDX SBOM, a `SHA256SUMS` file and a separately signed rule-pack bundle:

```bash
python -m pip install sigstore
python -m sigstore verify identity \
  --cert-identity "https://github.com/ak2dev/agentguard-v1/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  agentguard-X.Y.Z-py3-none-any.whl
```

## IOC feed signing

The IOC feed is signed with Ed25519. Trusted public keys ship in `intel/keys/`. The bundled `sample-2026-09` key signs only the synthetic sample feed; its private key was discarded after signing. Production feeds are signed with a maintainer key held offline, and `agentguard intel update` refuses unsigned feeds and any feed older than the last one accepted.

## What Agent Guard itself does

- No telemetry. Network access only with explicit opt-in flags, through an SSRF-hardened client.
- Parses, never executes: no imports of scanned code, no package managers, no containers.
- Bounded, hardened loaders: size, count, depth and decompression limits; no symlink following; YAML without anchors, aliases or custom tags; regex timeouts.
- Dependencies are pinned (`uv.lock`), and each release ships an SBOM.
