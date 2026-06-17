# Codex Window Keeper

CLIProxyAPI 插件：每天在固定时间点，给每个文件型 Codex OAuth 凭证各发一次轻量请求（`hi`），把每个号的 5 小时限额窗口固定到这些时段，避免窗口漂移。默认时间 `07:00`、`12:00`、`17:00`、`22:00`（可配置）。

## 构建

需按 CLIProxyAPI 的容器平台构建（下例为 `linux/arm64`）：

```bash
docker run --rm --platform linux/arm64 \
  -v "$PWD/codex-window-keeper":/src \
  -v "$PWD/plugins/linux/arm64":/out \
  -w /src golang:1.23-bookworm \
  sh -lc '/usr/local/go/bin/go build -buildmode=c-shared -o /out/codex-window-keeper.so .'
```

## 安装

把产物放进 CLIProxyAPI 的插件目录（插件 ID 取自文件名，必须是 `codex-window-keeper`）：

```text
plugins/linux/arm64/codex-window-keeper.so
```

## 配置

在 CLIProxyAPI 的 `config.yaml` 中启用并配置：

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

      # 可选：warm 那些被你设成较低 priority 的账号。
      # 不配 management_key 时，只会 warm 处于最高优先级层的账号。
      management_key: "<cliproxyapi 管理密钥原文>"
      # 以下均有默认值，通常无需修改：
      # management_base_url: "https://127.0.0.1:8317"
      # management_ca_cert: "/CLIProxyAPI/certs/cert.pem"
      # bump_priority: 10
```

除 `enabled` 外其余字段均有默认值，可按需省略。

## 使用

- 随 CLIProxyAPI 启动后，插件按 `times` 自动运行，无需干预。
- 更换 keepalive 模型：改 `config.yaml` 的 `model` 即可，无需重新构建 `.so`。
- 查看状态 / 最近一次运行结果，或手动触发一次运行：

  ```text
  https://127.0.0.1:8317/v0/resource/plugins/codex-window-keeper/status
  ```

> 状态页（及其手动触发）依赖管理端口仅绑定 loopback，请勿将该端口暴露到不可信网络。

## 许可证

[MIT](LICENSE) © 2026 yuhangrao
