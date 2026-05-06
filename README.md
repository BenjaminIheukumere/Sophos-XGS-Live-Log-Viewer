# Sophos XGS Live Log Viewer

Sophos XGS Live Log Viewer by Benjamin Iheukumere is a Windows desktop app for pulling Sophos XGS event logs on demand over SSH and showing them in near real time.

It is built for firewall troubleshooting when you do not want to deploy or reconfigure a Syslog server, but still need fast live visibility into blocked and allowed traffic.

* * *

## Features

  * On-demand SSH connection to Sophos XGS / Sophos Firewall appliances
  * Live log view with fast rolling UI window for high-volume traffic
  * Single active log source via dropdown: Firewall, Web filter, IPS, VPN, WAF, Email, System and more
  * Log switching inside the same SSH session
  * Color-coded rows for allowed and denied entries
  * Dynamic columns per selected log type
  * Column picker for additional fields
  * Clickable filter builder with connector, field, operator and value dropdowns
  * Per-firewall profiles
  * Local encrypted credential vault protected by a master password
  * SSH host key trust-on-first-use with fingerprint pinning
  * Appliance CPU usage display
  * Demo mode for parser, filter and UI testing without a firewall

* * *

## Requirements

  * Windows 10/11
  * Sophos Firewall / Sophos XGS with SSH access enabled
  * A firewall account allowed to open Advanced Shell
  * Sophos Advanced Shell with `sqlite3` available

The default source reads the Sophos event log database from `/tmp/eventlogs` or `/var/eventlogs`. This is intentional: Sophos Log Viewer categories are event-log based, while `/log/*.log` files are mostly service/troubleshooting logs.

* * *

## Installation

### Release build

Download the latest Windows release from:

`https://github.com/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer/releases`

Extract the ZIP and run:

```text
Sophos XGS Live Log Viewer by Benjamin Iheukumere.exe
```

### Build from source

```powershell
git clone https://github.com/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer.git
cd Sophos-XGS-Live-Log-Viewer
dotnet restore
dotnet test
dotnet publish .\SophosXgsLiveLogViewer.App\SophosXgsLiveLogViewer.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

* * *

## Usage

  1. Start the app.
  2. Create or unlock the local profile vault with a master password.
  3. Add a firewall profile with host, SSH port, username and password.
  4. Connect to the firewall.
  5. Select one live log source from the dropdown.
  6. Add filters through the dropdown-based filter builder if needed.

Profiles are stored locally in:

```text
%APPDATA%\SophosXgsLiveLogViewer\vault.json
```

The vault payload is encrypted with AES-GCM. The key is derived from the startup master password using PBKDF2-SHA256.

* * *

## Filter examples

The UI is dropdown based, but the filter engine supports combinations like:

```text
Source IP equals 192.168.1.10
Destination IP equals 8.8.8.8 AND Destination Port equals 443
Source IP not equals 192.168.1.99
Message contains blocked
```

Supported operators include:

  * Equals
  * Not equals
  * Contains
  * Not contains
  * Starts with
  * Ends with

* * *

## Performance notes

  * Incoming SSH log rows are queued and applied to the UI in batches.
  * The visible grid is a bounded rolling window.
  * A larger in-memory buffer is kept for filtering and log-source switching.
  * The app is optimized for troubleshooting visibility, not long-term log retention.

Use a SIEM, Syslog server or Sophos Central for durable audit storage.

* * *

## Security notes

  * No firewall credentials are stored in source code.
  * SSH host keys are pinned after trust-on-first-use.
  * Use least-privilege accounts where possible.
  * Run only against firewalls you own or administer.

* * *

## Contact

Benjamin Iheukumere

  * Website: https://safelink-it.com
  * Email: b.iheukumere@safelink-it.com
  * Phone: +49 177 3 555 059
  * LinkedIn: https://www.linkedin.com/in/benjamin-iheukumere/

* * *

## Disclaimer

This tool is intended for authorized administration and troubleshooting only. Use it only on systems where you have explicit permission. The author is not responsible for misuse.

## License

MIT
