<div align="center">

# 🧰 personal-scripts

**个人自用 Shell 脚本集合**
基于公开项目脚本做少量定向定制，仅覆盖自己的使用场景

<a href="#kejilion">🔧 kejilion.sh</a> ·
<a href="#traffic-dog">🐶 端口流量狗</a> ·
<a href="#self-detect">🔍 self-detect.sh</a> ·
<a href="#easy-caddy">🌐 easy_Caddy</a> ·
<a href="#ip-allowlist">🛡️ IP 白名单</a>

</div>

> [!WARNING]
> 脚本仅用于个人使用场景。执行前请自行审阅内容，并根据实际环境调整配置。

---

## 🗂 工具一览

| 工具 | 一句话定位 | 版本 | 上游 |
| :--- | :--- | :---: | :--- |
| [`kejilion.sh`](#kejilion) | Linux 运维工具箱（科技lion 定制版） | `v4.5.10` | [kejilion/sh](https://github.com/kejilion/sh) |
| [`port-traffic-dog.sh`](#traffic-dog) | 按端口统计与限制流量 | `v1.2.5` | [zywe03/realm-xwPF](https://github.com/zywe03/realm-xwPF/blob/main/port-traffic-dog-README.md) |
| [`self-detect.sh`](#self-detect) | OpenGFW + Nmap 本机端口自查 | `v3.2.5` | [duya07/personal-scripts](https://github.com/duya07/personal-scripts) |
| [`easy_Caddy`](#easy-caddy) | Caddy 部署 / 反代 / 证书同步 | — | [duya07/easy_Caddy](https://github.com/duya07/easy_Caddy) |
| [`ip-port-allowlist.sh`](#ip-allowlist) | IPv4/IPv6 TCP/UDP 端口白名单与连接日志 | — | — |

<br>

<a id="kejilion"></a>

## 🔧 1 · kejilion.sh —— 科技lion 工具箱

科技lion 工具箱的个人定制版，本仓库脚本版本标记为 **`v4.5.10`**。

**本库定制**

- 🔕 **关闭埋点上报**：`send_stats()` 函数体已置空，且默认 `ENABLE_STATS="false"`；全文可搜 `send_stats` 调用位置自行核对。
- 🌐 **默认走 gh-proxy**：默认参数 `canshu="CN"`，GitHub 资源经 `https://v6.gh-proxy.org/` 拉取（`canshu="V6"` 同样走代理，其他取值直连）。
- 🔄 **自更新指向本仓库**：脚本内置的手动更新与定时更新均从 `duya07/personal-scripts` 拉取，更新逻辑保留 `ENABLE_STATS="false"` 与许可同意状态。
- ✅ **跳过首次许可确认**：预设 `permission_granted="true"`。

**安装并运行**

```bash
wget -O kejilion.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/kejilion.sh && chmod +x kejilion.sh && sudo bash ./kejilion.sh
```

首次运行会把脚本安装为 `/usr/local/bin/k`，之后直接输入 `k` 即可唤起。

<br>

<a id="traffic-dog"></a>

## 🐶 2 · port-traffic-dog.sh —— 端口流量狗

按端口统计流量、设置限额 / 自动重置，支持 Telegram、企业微信通知。配置与数据存放于 `/etc/port-traffic-dog/`。

**本库定制**

- 📦 通知模块按需同步到实际运行目录 `/etc/port-traffic-dog/notifications/`。
- 🗂 优先使用**主脚本同目录**下自维护的 `telegram.sh` / `wecom.sh`，复制进配置目录。
- 🛡 从上游下载时只补齐缺失的通知模块，不覆盖已存在的文件。

> [!CAUTION]
> 当前修改尚未完全测试，请在生产环境使用前先自行验证。
>
> 脚本菜单内的「安装依赖(更新)脚本」会从上游 `zywe03/realm-xwPF` 拉取并替换主脚本，可能丢失本库对通知模块同步流程的定制。

**安装并运行**（需 root，仅支持 Ubuntu / Debian，缺失依赖会自动安装）：

```bash
sudo wget -O /usr/local/bin/port-traffic-dog.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/port-traffic-dog.sh && sudo chmod +x /usr/local/bin/port-traffic-dog.sh && sudo /usr/local/bin/port-traffic-dog.sh
```

脚本会创建快捷命令 `dog`，之后直接输入 `sudo dog` 即可进入菜单。

<br>

<a id="self-detect"></a>

## 🔍 3 · self-detect.sh —— 本机端口自查

Nmap 扫描监听端口，按 OpenGFW 分析器逻辑做风险分类，生成 Markdown 报告与 OpenGFW 规则建议（YAML）；可选抓包后用 OpenGFW 回放验证，支持 iptables 一键阻断/放行、常驻 daemon 与 systemd 安装。

### 📦 依赖

| 场景 | 所需组件 |
| :--- | :--- |
| 基础 | `ss` `nmap` `awk` `grep` `sed` `curl` `openssl` |
| 回放模式（`--run-opengfw-replay`） | 另需 `tcpdump` + OpenGFW 二进制 |

```bash
sudo apt install -y nmap tcpdump iproute2 curl openssl
```

### 🧩 OpenGFW 二进制（回放模式必需）

脚本默认在**当前工作目录**找 `OpenGFW-linux-amd64`；内置自动下载地址是占位符（`http://10.10.10.10/...`），需自行提供。可直接用本仓库附带的二进制：

```bash
wget --user-agent="Mozilla/5.0" -O OpenGFW-linux-amd64 https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/OpenGFW-linux-amd64
chmod +x OpenGFW-linux-amd64
```

或用参数指定：`--opengfw-url <URL>` 更换下载地址，`--opengfw-bin <PATH>` 指定本地二进制路径，`--skip-download-opengfw` 关闭自动下载。

> [!IMPORTANT]
> 🔴 **默认上传报告**：`REPORT_ENABLED=1`，扫描结果会以 JSON 上传到 `http://netreport.leikwanhost.com/report`。不需要请加 `--disable-report`，或用 `--report-url <URL>` 改成自己的接收端。

### 🚀 下载并运行

```bash
sudo wget -O self-detect.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/self-detect.sh && sudo chmod +x self-detect.sh

# 快速扫描（本例关闭报告上传和 OpenGFW 自动下载）
sudo bash self-detect.sh --quick --disable-report --skip-download-opengfw

# 完整扫描 + OpenGFW 回放验证 + 关闭报告上传
sudo bash self-detect.sh --full --run-opengfw-replay --disable-report

# 查看全部参数
bash self-detect.sh --help
```

<br>

<a id="easy-caddy"></a>

## 🌐 4 · easy_Caddy —— Caddy 部署管理

[duya07/easy_Caddy](https://github.com/duya07/easy_Caddy) —— Debian/Ubuntu 上的 Caddy 单文件 Bash 部署与管理工具，源码与使用说明维护在该仓库。

- **部署与代理**：安装 Caddy、依赖检测、配置反向代理（本地端口 / 远程网址）。
- **服务运维**：状态与反代配置查看、删除反代、重启、日志查看与日志轮转（按日 / 周 / 月）。
- **维护**：证书查看与复制同步、域名日志、手动编辑配置（应用前先校验）、卸载与依赖管理。

安装命令与完整说明见该仓库 README。

<a id="ip-allowlist"></a>

## 🛡️ 5 · ip-port-allowlist.sh —— IP / 端口白名单

Linux 下按端口做 IPv4/IPv6、TCP/UDP、IP/CIDR 来源白名单与「拒绝全部来源」封锁；覆盖目标配置、编辑、移除、实际规则查看与事务恢复。无参数启动交互菜单（root），带参走 CLI。

- **菜单**：1–9 / 0 / 条件 R 原有语义不变，新增 10 日志、11 日志轮转与清除设置；子页面共用面板标题。
- **依赖**：Bash 4.4+（不可用 `sh`）、完整 Perl 核心模块与兼容 Linux 工具（`iptables`/`ip6tables`/`iproute2`/`flock`/`sync`/`timeout` 等），不依赖 Python / jq。
- **检测**：`doctor` 仅检测；`doctor --install` 需显式输入 `yes` 才会安装缺失依赖。
- **状态与日志**：状态默认 `/root/.ip-port-allowlist.json`，日志目录 `/root/.ip-port-allowlist.logs`；可用 `IP_PORT_ALLOWLIST_DIR` 隔离文件，但不隔离受管链归属（仍需 `unshare -n` 隔离测试）。
- **日志**：`operations` 默认 `on`，`connections` 默认 `off`（可设 `deny`/`all`）；连接日志为非终止 LOG 在既有 RETURN/DROP 前的限速数据包采样，`RETURN` 仅表示本脚本来源规则命中，不代表后续 filter 最终接受。查看时触发有界采集（`journalctl` 仅读本实例 prefix），来源暂不可用时仍可读取已保存记录。
- **轮转与清理**：按 `max_mib`/`keep`/`retention_days`/`rate`/`burst`/`auto_rotate` 设置管理（默认 10 MiB / 5 份 / 30 天 / 10 次采样/分钟 / 突发 5 / 自动轮转 on，限速为包匹配限速）；`log-rotate`/`log-clear --confirm CLEAR` 仅清理本脚本私有文件，不删除系统 journal，不建 cron/daemon。

### 🚀 下载

```bash
# 中文版
wget -O ip-port-allowlist.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/ip-port-allowlist.sh && chmod +x ip-port-allowlist.sh
# 英文版（仅消息文本不同，行为一致）
wget -O ip-port-allowlist-en.sh https://v6.gh-proxy.org/https://raw.githubusercontent.com/duya07/personal-scripts/main/ip-port-allowlist-en.sh && chmod +x ip-port-allowlist-en.sh
```

```bash
# 无参数进菜单（需 root）
sudo bash ./ip-port-allowlist.sh
# 中英文分别直接执行
sudo bash ./ip-port-allowlist-en.sh
```

### 🧩 常用 CLI（示例 IP/端口请替换为实际值，执行真实修改前请自行备份）

```bash
# 预检（不改状态/规则）
sudo bash ./ip-port-allowlist.sh validate --ips 203.0.113.10 --ports 8443 --family 4 --proto both

# 配置目标主机地址（仅 /32 或 /128，需替换为服务器自身目标地址；如首次为空或旧版 v1 状态，有非 lo global 地址时会自动探测目标）
sudo bash ./ip-port-allowlist.sh targets --family 4 --ips 203.0.113.20

# 设置/替换白名单（family 默认 auto，remove/block 默认 both；仅当对应族无目标时需先 targets 配置，示例来源 203.0.113.10 与目标 203.0.113.20 独立）
sudo bash ./ip-port-allowlist.sh set --ips 203.0.113.10 --ports 8443 --family 4 --proto both

# 查看
sudo bash ./ip-port-allowlist.sh show --json
sudo bash ./ip-port-allowlist.sh show --live --json

# 日志：查看与设置（type 默认 both，lines 默认 50；支持 --json）
sudo bash ./ip-port-allowlist.sh logs --type both --lines 50
sudo bash ./ip-port-allowlist.sh logs --status
sudo bash ./ip-port-allowlist.sh log-settings --json
sudo bash ./ip-port-allowlist.sh log-settings --set connections deny
sudo bash ./ip-port-allowlist.sh log-rotate --type both
sudo bash ./ip-port-allowlist.sh log-clear --type both --confirm CLEAR
```

> [!TIP]
> 查看连接日志前需先将 `connections` 设为 `deny` 或 `all`；设置后会重建受管链，仅新增 LOG 规则。

- **SSH 防误封**：变更前会检查 `SSH_CONNECTION`，若会阻断当前 SSH 来源则拒绝写入。
- **事务与恢复**：失败或可捕获的中断/异常自动回滚内核/状态；强制终止后保留 journal，下次 `recover` 恢复；状态文件损坏时用 `repair-state --from-live/--empty` 引导修复，未完成事务优先 `recover`。
- **开机恢复**：保存状态不等于开机自动恢复，`restore` 需自行安排启动任务，不会自动创建服务。

<br>

---

## 📌 注意事项

- 脚本可能修改系统配置或安装依赖，建议先在测试环境运行。
- 如需使用通知功能，请提前准备好 Telegram Bot / 企业微信相关配置。
- 所有下载命令默认走 `v6.gh-proxy.org` 代理；若下载失败，可检查代理可用性，或手动替换为可访问的 `raw.githubusercontent.com` 直连地址。

<div align="center">

<sub>personal-scripts · 个人自用，按需自取</sub>

</div>
