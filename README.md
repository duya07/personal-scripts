# personal-scripts

个人自用 Shell 脚本集合：基于公开项目脚本做少量定向定制，仅覆盖自己的使用场景。

> ⚠️ 脚本仅用于个人使用场景。执行前请自行审阅内容，并根据实际环境调整配置。

## 🧰 工具一览

| 工具 | 作用 | 版本 | 来源 |
| --- | --- | --- | --- |
| `kejilion.sh` | Linux 运维工具箱 | v4.5.10 | [kejilion/sh](https://github.com/kejilion/sh) |
| `port-traffic-dog.sh` | 按端口统计与限制流量 | v1.2.5 | [zywe03/realm-xwPF](https://github.com/zywe03/realm-xwPF/blob/main/port-traffic-dog-README.md) |
| `self-detect.sh` | OpenGFW + Nmap 本机端口自查 | v3.2.5 | [duya07/personal-scripts](https://github.com/duya07/personal-scripts) |
| `easy_Caddy` | Caddy 部署 / 反代 / 证书同步 | — | [duya07/easy_Caddy](https://github.com/duya07/easy_Caddy) |

---

## 1. kejilion.sh

科技lion 工具箱的个人定制版，本仓库脚本版本标记为 **v4.5.10**。

**本库定制**

- 🔕 **关闭埋点上报**：`send_stats()` 函数体已置空，且默认 `ENABLE_STATS="false"`；全文可搜 `send_stats` 调用位置自行核对。
- 🌐 **默认走 gh-proxy**：默认参数 `canshu="CN"`，GitHub 资源经 `https://v6.gh-proxy.org/` 拉取（`canshu="V6"` 同样走代理，其他取值直连）。
- 🔄 **自更新指向本仓库**：脚本内置的手动更新与定时更新均从 `duya07/personal-scripts` 拉取，更新逻辑保留 `ENABLE_STATS="false"` 与许可同意状态。
- ✅ 预设 `permission_granted="true"`，跳过首次运行的许可协议确认。

**安装并运行**

```bash
wget -O kejilion.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/kejilion.sh && chmod +x kejilion.sh && sudo bash ./kejilion.sh
```

首次运行会把脚本安装为 `/usr/local/bin/k`，之后直接输入 `k` 即可唤起。

---

## 2. port-traffic-dog.sh · 端口流量狗

按端口统计流量、设置限额 / 自动重置，支持 Telegram、企业微信通知。配置与数据存放于 `/etc/port-traffic-dog/`。

**本库定制**

- 📦 通知模块按需同步到实际运行目录 `/etc/port-traffic-dog/notifications/`。
- 🗂 优先使用**主脚本同目录**下自维护的 `telegram.sh` / `wecom.sh`，复制进配置目录。
- 🛡 从上游下载时只补齐缺失的通知模块，不覆盖已存在的文件。

> ⚠️ 当前修改尚未完全测试，请在生产环境使用前先自行验证。
>
> 脚本菜单内的「安装依赖(更新)脚本」会从上游 `zywe03/realm-xwPF` 拉取并替换主脚本，可能丢失本库对通知模块同步流程的定制。

**安装并运行**（需 root，仅支持 Ubuntu / Debian，缺失依赖会自动安装）：

```bash
sudo wget -O /usr/local/bin/port-traffic-dog.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/port-traffic-dog.sh && sudo chmod +x /usr/local/bin/port-traffic-dog.sh && sudo /usr/local/bin/port-traffic-dog.sh
```

脚本会创建快捷命令 `dog`，之后直接输入 `sudo dog` 即可进入菜单。

---

## 3. self-detect.sh

本机端口自查脚本：Nmap 扫描监听端口，按 OpenGFW 分析器逻辑做风险分类，生成 Markdown 报告与 OpenGFW 规则建议（YAML）；可选抓包后用 OpenGFW 回放验证，支持 iptables 一键阻断/放行、常驻 daemon 与 systemd 安装。

**依赖**

- 基础：`ss` `nmap` `awk` `grep` `sed` `curl` `openssl`
- 回放模式（`--run-opengfw-replay`）另需：`tcpdump` + OpenGFW 二进制

```bash
sudo apt install -y nmap tcpdump iproute2 curl openssl
```

**OpenGFW 二进制（回放模式必需）**

脚本默认在**当前工作目录**找 `OpenGFW-linux-amd64`；内置自动下载地址是占位符（`http://10.10.10.10/...`），需自行提供。可直接用本仓库附带的二进制：

```bash
wget --user-agent="Mozilla/5.0" -O OpenGFW-linux-amd64 https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/OpenGFW-linux-amd64
chmod +x OpenGFW-linux-amd64
```

或用参数指定：`--opengfw-url <URL>` 更换下载地址，`--opengfw-bin <PATH>` 指定本地二进制路径，`--skip-download-opengfw` 关闭自动下载。

> 🔴 **默认上传报告**：`REPORT_ENABLED=1`，扫描结果会以 JSON 上传到 `http://netreport.leikwanhost.com/report`。不需要请加 `--disable-report`，或用 `--report-url <URL>` 改成自己的接收端。

**下载并运行**

```bash
sudo wget -O self-detect.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/self-detect.sh && sudo chmod +x self-detect.sh

# 快速扫描（本例关闭报告上传和 OpenGFW 自动下载）
sudo bash self-detect.sh --quick --disable-report --skip-download-opengfw

# 完整扫描 + OpenGFW 回放验证 + 关闭报告上传
sudo bash self-detect.sh --full --run-opengfw-replay --disable-report

# 查看全部参数
bash self-detect.sh --help
```

---

## 4. easy_Caddy

[duya07/easy_Caddy](https://github.com/duya07/easy_Caddy) — Debian/Ubuntu 上的 Caddy 单文件 Bash 部署与管理工具，源码与使用说明维护在该仓库。

- **部署与代理**：安装 Caddy、依赖检测、配置反向代理（本地端口 / 远程网址）。
- **服务运维**：状态与反代配置查看、删除反代、重启、日志查看与日志轮转（按日 / 周 / 月）。
- **维护**：证书查看与复制同步、域名日志、手动编辑配置（应用前先校验）、卸载与依赖管理。

安装命令与完整说明见该仓库 README。

---

## 📌 注意事项

- 脚本可能修改系统配置或安装依赖，建议先在测试环境运行。
- 如需使用通知功能，请提前准备好 Telegram Bot / 企业微信相关配置。
- 所有下载命令默认走 `v6.gh-proxy.org` 代理；若下载失败，可检查代理可用性，或手动替换为可访问的 `raw.githubusercontent.com` 直连地址。
