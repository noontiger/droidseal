# Contributing to DroidSeal

[中文](CONTRIBUTING.zh-CN.md) | [English](CONTRIBUTING.md)

Thank you for helping improve DroidSeal. The project accepts bug fixes, copy and accessibility improvements, tests, platform compatibility fixes, and features for the secure release of legitimate Android applications.

By participating in the community you agree to abide by the [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Do not file security vulnerabilities as public issues; follow [SECURITY.md](SECURITY.md) instead.

## Project governance

DroidSeal uses Maintainer-led governance. Maintainers are responsible for project direction, security boundaries, compatibility commitments, release quality, and final merge decisions; see [GOVERNANCE.md](GOVERNANCE.md). Large architectural changes, new download sources, or new security controls should be discussed before being implemented.

## Developer Certificate of Origin

DroidSeal accepts external contributions under the Developer Certificate of Origin 1.1 (DCO). Every commit must carry a valid `Signed-off-by` line confirming the committer has the right to contribute under the project license.

Create a signed commit:

```bash
git commit -s
```

The resulting commit message should contain:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name or an identity you may lawfully use; do not sign on behalf of others. The full DCO 1.1 text is at <https://developercertificate.org/>.

## Development environment

Requirements:

- Bun 1.3 or newer;
- a supported interactive terminal;
- JDK, Android SDK and Build Tools matching the flows under test.

```bash
bun install --frozen-lockfile
bun run dev
```

Run before committing:

```bash
bun run verify
```

`verify` runs strict TypeScript checks, tests, the build, and the open-source release check in sequence.

## Contribution scope

Welcome:

- defensive audits of APK, Manifest, ZIP, DEX and SO;
- Gradle, R8, zipalign, keytool and apksigner workflows;
- improvements to the opt-in build-time anti-debug stub and security audit baselines;
- transactional rollback, redaction, error explanations and TUI accessibility;
- Windows, macOS and Linux compatibility;
- documentation, tests, report formats and release engineering improvements.

Not accepted:

- unauthorized unpacking, hooks, certificate verification bypasses, or security detection evasion;
- stealing signing keys, credentials, or protected code;
- committing real APKs, AABs, JKS, PKCS12, private keys, or passwords to the repository;
- behavior that silently downloads, executes, or uploads user files.

## Pull Request requirements

1. One clear issue per PR.
2. Every commit carries a valid DCO `Signed-off-by` line.
3. Behavior changes must include tests; copy changes should cover key branches.
4. Do not commit `node_modules`, `dist`, `.droidseal`, APKs, or signing material.
5. New dependencies must explain purpose, license, maintenance status, and why existing dependencies cannot be used.
6. External commands must be launched as argument arrays, not concatenated shell strings.
7. All passwords must be passed through the child process environment and added to the output redaction list.
8. Failure paths must preserve or restore the previous valid APK.
9. User-visible changes should update README and CHANGELOG.
10. Run `bun run verify` before committing.

## Security-sensitive changes

When a change touches process execution, argument parsing, path normalization, archive handling, automatic downloads, checksums, signing credentials, keystores, output redaction, network access, or permission changes, the PR must state the security impact, threat boundary, and verification approach, and be reviewed by CODEOWNERS.

## Reporting ordinary bugs

Use the Bug Report template and provide:

- the DroidSeal version;
- OS, terminal, Bun, JDK and Android Build Tools versions;
- the input type (APK or project); do not upload real applications;
- step name, error code, and redacted output;
- a minimal reproduction.

## Contribution licensing

Unless explicitly agreed otherwise, source code, tests, documentation, and example contributions are distributed under the Apache License 2.0. The DCO signature proves you have the right to submit the contribution; it does not transfer copyright to the maintainers.
