# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through GitHub's [private vulnerability reporting](https://github.com/xsignon-secure/Chimera/security/advisories/new).

Include what you found, how to reproduce it, and the version or commit you tested. We aim to acknowledge reports within 3 business days and to ship a fix or mitigation for confirmed issues within 30 days, and we will credit you in the release notes unless you ask us not to.

## Scope

In scope: anything that lets an attacker who talks to the decoy escape it, reach the responder beyond its one alert endpoint, reach other hosts, run code, read real data, or tamper with the audit log. Also in scope: the installer, the published container image and `chimera-ctl`.

Out of scope: the fake secrets the decoy hands out (they are synthetic on purpose) and fingerprinting that reveals the decoy is a honeypot, although we welcome ideas to make it harder.

## Supported versions

Security fixes go to the latest release and to `main`.

The full threat model, with the test that proves each control, is in [docs/SECURITY.md](docs/SECURITY.md).
