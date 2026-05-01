# personal-scripts

个人自用 Shell 脚本集合，主要基于公开项目脚本进行适配和小幅修改。

> 脚本仅用于个人使用场景，请在执行前自行审阅内容，并根据实际环境调整配置。

## 脚本列表

### 1. kejilion.sh

来源：[kejilion/sh](https://github.com/kejilion/sh)

修改说明：
- 仅关闭默认上传功能，版本v4.4.10。

安装并运行：

```bash
wget -O kejilion.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/kejilion.sh && chmod +x kejilion.sh && ./kejilion.sh
```

### 2. 端口流量狗

#### 2.1 port-traffic-dog.sh

来源：[realm-xwPF/port-traffic-dog-README.md](https://github.com/zywe03/realm-xwPF/blob/main/port-traffic-dog-README.md)

修改说明：

- 优先使用 `port-traffic-dog.sh` 同目录下的 `telegram.sh` / `wecom.sh` 通知模块。
- 本地通知模块会同步到实际运行目录：`/etc/port-traffic-dog/notifications/`。
- 如果 `telegram.sh` 和 `wecom.sh` 两个通知模块都已存在，则不会再从 GitHub 下载并覆盖。
- 如果缺少通知模块，仅从 GitHub 补齐缺失文件，不覆盖已有文件。

> 当前修改尚未完全测试，请在生产环境使用前先进行验证。

安装并运行：

```bash
wget -O port-traffic-dog.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/port-traffic-dog.sh && chmod +x port-traffic-dog.sh && ./port-traffic-dog.sh
```

Alpine 安装并运行：

```bash
wget -O alpine-port-traffic-dog-preinstall.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/alpine-port-traffic-dog-preinstall.sh && chmod +x alpine-port-traffic-dog-preinstall.sh && ./alpine-port-traffic-dog-preinstall.sh && wget -O port-traffic-dog.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/port-traffic-dog.sh && chmod +x port-traffic-dog.sh && ./port-traffic-dog.sh
```

#### 2.2 telegram.sh

修改说明：

- 修改默认 Telegram API 路径，以便在大陆网络环境下使用。

安装：

```bash
wget -O telegram.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/telegram.sh && chmod +x telegram.sh
```


## 注意事项

- 脚本可能会修改系统配置或安装依赖，建议先在测试环境运行。
- 如需使用通知功能，请提前准备好 Telegram 或企业微信相关配置。
- 若脚本下载失败，可检查代理地址或手动替换为可访问的 raw GitHub 地址。
