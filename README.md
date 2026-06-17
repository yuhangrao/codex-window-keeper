# Codex Window Keeper

A CLIProxyAPI plugin that sends a lightweight request (`hi`) to each file-based Codex OAuth credential at fixed times every day, pinning each account's 5-hour rate-limit window to those slots so it doesn't drift. Default times are `07:00`, `12:00`, `17:00`, `22:00` (configurable).

## Build

Build for the CLIProxyAPI container platform (the example targets `linux/arm64`):

```bash
docker run --rm --platform linux/arm64 \
  -v "$PWD/codex-window-keeper":/src \
  -v "$PWD/plugins/linux/arm64":/out \
  -w /src golang:1.23-bookworm \
  sh -lc '/usr/local/go/bin/go build -buildmode=c-shared -o /out/codex-window-keeper.so .'
```

## Install

Drop the build artifact into CLIProxyAPI's plugin directory (the plugin ID is taken from the filename, so it must be `codex-window-keeper`):

```text
plugins/linux/arm64/codex-window-keeper.so
```

## Configuration

Enable and configure it in CLIProxyAPI's `config.yaml`:

```yaml
plugins:
  enabled: true
  dir: "/CLIProxyAPI/plugins"
  configs:
    codex-window-keeper:
      enabled: true
      timezone: "Asia/Shanghai"
      times: ["07:00", "12:00", "17:00", "22:00"]
      model: "gpt-5.4"

      # Optional: also warm accounts you've set to a lower priority.
      # Without management_key, only accounts in the top priority tier are warmed.
      management_key: "<raw cliproxyapi management key>"
      # These have defaults and usually need no change:
      # management_base_url: "https://127.0.0.1:8317"
      # management_ca_cert: "/CLIProxyAPI/certs/cert.pem"
      # bump_priority: 10
```

Every field except `enabled` has a default and may be omitted.

## Usage

- Once CLIProxyAPI starts, the plugin runs automatically at each time in `times` — no intervention needed.
- To change the keepalive model, edit `model` in `config.yaml`; rebuilding the `.so` is not required.
- To view status — each credential's last result and its next scheduled run — or trigger a run manually:

  ```text
  https://127.0.0.1:8317/v0/resource/plugins/codex-window-keeper/status
  ```

> The status page (and its manual trigger) relies on the management port being bound to loopback only — do not expose that port to an untrusted network.

## License

[MIT](LICENSE) © 2026 yuhangrao
