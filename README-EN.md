**Languages:** [Русский](README.md) | [English](README-EN.md) 

# Web Liberty (Chrome Extension)

Manage multiple SOCKS5 / SOCKS4 / HTTP / HTTPS proxies and switch between them with one click. Optional per-domain whitelist/blacklist routing. Light/dark theme follows the OS.

![Popup](./img1.png)

![Popup](./img2.png)


## Features

- Add unlimited proxy profiles (`socks5`, `socks4`, `http`, `https`).
- One-click switch between profiles or **Direct** (no proxy).
- Optional credentials for HTTP(S) proxies (auto-supplied via `webRequest.onAuthRequired`).
- Domain filtering modes:
  - **All websites are allowed** — proxy is used for all sites.
  - **Whitelist only** — proxy is used **only** for listed domains.
  - **Blacklist deny** — proxy is used for everything **except** listed domains.
- Toolbar icon reflects current state (on/off); no badge text clutter.
- Light/dark theme follows the OS color scheme.
- Domain patterns support bare domains (subdomain match) and `*` wildcards, e.g. `example.com`, `*.github.com`, `*google*`.
- Local/private addresses (RFC1918, loopback, `*.local`) always go direct.
- Export / import your configuration as JSON.

## Install (unpacked)

1. Create a folder: `C:\Users\<YOUR_NAME>\Documents\Chrome Extensions\WebLiberty`.
2. Copy the extension files into that folder.
3. Open `chrome://extensions/`.
4. Enable **Developer mode** (top-right).
5. Click **Load unpacked** and select the `WebLiberty` folder.
6. Pin the extension. Click the icon → ⚙ to open settings.

## Usage

1. **Popup**: pick the active server or **Direct**. Use **+ Add proxy** to jump to the settings page and create one. The **Edit** buttons next to *Whitelist only* / *Blacklist deny* open the corresponding domain list.
2. **Settings page**: add one or more proxy servers (name, scheme, host, port, optional username/password). The **Active** radio in the table marks which profile is currently applied; leaving all unchecked equals Direct.
3. **Domain filter**: choose mode and edit the domain lists. Bare domains match subdomains; `*` wildcard is supported.

## Notes on schemes

- `socks5` — DNS may be resolved remotely by the proxy depending on Chrome's policy.
- `socks4` — auth not supported by SOCKS4.
- `http` / `https` — username/password are sent automatically when the proxy challenges with `407`.

## Icons

The `icons/` folder must contain `on16/32/48/128.png` (proxy active) and `off16/32/48/128.png` (Direct). The toolbar icon switches between them automatically based on state.
