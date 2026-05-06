# Security Policy

## Supported versions

The latest release is the only supported version.

## Reporting a vulnerability

Please report security issues privately to:

`b.iheukumere@safelink-it.com`

Do not open public GitHub issues for vulnerabilities or credential exposure.

## Credential handling

Firewall profiles are stored locally under `%APPDATA%\SophosXgsLiveLogViewer\vault.json`.
The vault payload is encrypted with AES-GCM and a key derived from the startup master password using PBKDF2-SHA256.

Do not commit vault files, `.local` test files, firewall exports, packet captures, or real log samples.
