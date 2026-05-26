# Digital Guard

<p align="center">
  <img src="icon128.png" alt="Digital Guard" width="180">
</p>

<p align="center">
  <strong>Browser extension that warn and block known malicious Browser extensions installed</strong>
</p>

Digital Guard compares your installed browser extensions against the [ExtSentry community threat intelligence feed](https://github.com/ExtSentry/ExtSentry.github.io) and alerts you when a known malicious extension is detected. Threats are automatically disabled and a persistent warning guides you through removal.

## How it works

1. **Fetches** the latest blocklist of malicious extension IDs from the [ExtSentry feed](https://raw.githubusercontent.com/ExtSentry/ExtSentry.github.io/refs/heads/main/feeds/ioc_malicious_extension_ids.txt)
2. **Scans** all installed extensions on browser startup, after each feed update, and immediately when a new extension is installed
3. **Disables** any detected threat automatically (enabled by default)
4. **Warns** with a full-page alert showing the extension name, ID, permissions, and removal buttons
5. **Repeats** the warning every 5 minutes until all threats are uninstalled

## Features

- **Auto-sync** - fetches the blocklist every 30 minutes using ETag/Last-Modified caching for efficiency
- **Instant detection** - scans on startup and triggers immediately on new extension installs
- **Auto-disable** - malicious extensions are disabled the moment they are detected, before you see the warning
- **Persistent warnings** - full-page alerts with one-click uninstall/disable buttons, repeating until threats are removed
- **Uninstall nudging** - detects when the user dismisses the Chrome uninstall dialog and keeps prompting
- **Detection history** - logs every detection with timestamps and extension IDs
- **Custom blocklist** - add your own extension IDs to monitor alongside the community feed (import/export supported)
- **Custom feed URLs** - add additional feed sources returning one extension ID per line
- **Whitelist** - mark false positives as trusted to exclude from future scans
- **Force feed update** - manually trigger a fresh download bypassing the cache
- **Test mode** - simulate a warning with a random installed extension to verify the system works
- **Badge indicator** - red badge count on the toolbar icon when threats are active

## Installation

### Chrome Web Store

Install from the [Chrome Web Store](https://chromewebstore.google.com/detail/extsentry-guard/oiapejoklmgleheehkpgnpgmpibmoppm) !

### Manual install (developer mode)

1. Download or clone this repository
2. Open `chrome://extensions` in your browser
3. Enable **Developer mode** (top right toggle)
4. Click **Load unpacked** and select the extension folder
5. The Digital Guard icon appears in your toolbar

## Screenshot

<img width="404" height="598" alt="Capture d&#39;écran 2026-04-07 105513" src="https://github.com/user-attachments/assets/21322531-796e-456a-b807-e53bd8c64192" />


<img width="396" height="345" alt="Capture d&#39;écran 2026-04-07 105458" src="https://github.com/user-attachments/assets/0ee1f99f-f4fb-4251-a435-3e51b728bce3" />


## Permissions

| Permission | Why |
|---|---|
| `management` | List installed extensions, check IDs against the blocklist, disable and uninstall malicious extensions |
| `alarms` | Schedule periodic feed sync (every 30 min) and warning repeat (every 5 min) |
| `storage` | Persist blocklist, settings, detection history, and cached HTTP headers. Read enterprise policies via storage.managed |
| `notifications` | Display desktop notifications when threats are detected |
| `host_permissions` | Fetch the blocklist feed from raw.githubusercontent.com and any user-configured custom feed URLs |

## Feed source

The default blocklist is sourced from the [ExtSentry threat intelligence feed](https://github.com/ExtSentry/ExtSentry.github.io), which is maintained by the community and generated from [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists). The feed includes extensions categorized as malicious, phishing, deceptive, offensive, greyware, and more.

The feed file used by this extension:
```
https://raw.githubusercontent.com/ExtSentry/ExtSentry.github.io/refs/heads/main/feeds/ioc_malicious_extension_ids.txt
```

Plain text, one extension ID per line. You can add your own feeds in the same format from the Settings tab.

## Enterprise deployment

Digital Guard supports remote configuration via Chrome managed storage, allowing admins to push policies through GPO (Windows), MDM profiles (macOS), or JSON policy files (Linux/ChromeOS).

### Configurable policy fields

| Field | Type | Description |
|---|---|---|
| `feed_urls` | string[] | Blocklist feed URLs (default: ExtSentry GitHub feed) |
| `custom_blocklist` | string[] | Admin-managed extension IDs to block |
| `whitelist` | string[] | Extension IDs to always allow |
| `auto_disable` | boolean | Auto-disable threats on detection (default: true) |
| `check_interval_minutes` | integer | Feed sync interval (default: 30) |
| `warn_interval_minutes` | integer | Warning repeat interval (default: 5) |
| `lock_settings` | boolean | Prevent users from changing settings |
| `org_name` | string | Organization name shown in the UI |
| `org_message` | string | Custom message on the warning page |

## Privacy

Digital Guard runs entirely locally. It does not collect, transmit, or store any personal data. The only network requests are GET requests to fetch public blocklist text files from GitHub (or custom feed URLs you configure). No telemetry, no analytics, no tracking.

## Project structure

```
├── manifest.json          # Extension manifest (Manifest V3)
├── background.js          # Service worker: feed sync, scanning, messaging
├── popup.html             # Toolbar popup UI
├── popup.js               # Popup logic: dashboard, settings, history
├── warning.html           # Full-page warning shown for detected threats
├── warning.js             # Warning page logic: threat cards, actions
├── managed_schema.json    # Schema for enterprise managed storage policies
├── icon16.png             # Toolbar icon 16px
├── icon32.png             # Toolbar icon 32px
├── icon48.png             # Extension icon 48px
└── icon128.png            # Extension icon 128px
```

## Contributing

Found a malicious extension not in the feed? The upstream data lives in [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists). Open a pull request there to add it.

For bugs, feature requests, or improvements to the extension itself, open an issue or PR on this repository.
