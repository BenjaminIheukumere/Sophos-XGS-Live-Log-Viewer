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

## Secure operation

Use the app from a secured admin workstation only:

* keep Windows and security tooling patched;
* prefer a dedicated admin network, bastion host or trusted VPN path;
* avoid shared or unmanaged devices;
* keep disk encryption enabled;
* prevent screen, clipboard and session snooping;
* use a least-privilege firewall admin account where possible.

SSH profiles default to Strict mode, which removes legacy key exchange, cipher, MAC and host-key algorithms from SSH.NET negotiation. Use Compatibility mode only when an older appliance cannot negotiate Strict mode, and document that exception.

Incident captures and filter exports can contain operationally sensitive data. Filter exports do not include firewall hostnames, usernames, passwords, profiles or vault data, but captures can include IP addresses, usernames, URLs, domains and raw firewall log content.
