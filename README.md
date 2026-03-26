# Apifox IOC 检测脚本

用于快速排查与公开披露的 Apifox 供应链事件相关的本地 IOC、日志痕迹和基础持久化痕迹。

> 这是一个本地 IOC 排查工具，不是完整取证工具。

## 概述

当前目录包含两个脚本：

- [apifox_macos_ioc_check.sh](/Users/espoir/Downloads/apifox/apifox_macos_ioc_check.sh)
- [apifox_windows_ioc_check.ps1](/Users/espoir/Downloads/apifox/apifox_windows_ioc_check.ps1)

适用平台：

- `apifox_macos_ioc_check.sh`：用于 macOS
- `apifox_windows_ioc_check.ps1`：用于 Windows

参考分析：

- https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/

## 功能

两个脚本都围绕同一批公开 IOC 和行为点进行排查，重点包括：

- Apifox 本地安装、缓存、配置、日志目录
- Electron `Local Storage` / `leveldb` 中的 IOC 字符串
- shell 或 PowerShell 历史中的可疑域名和路径
- 与 `apifox.it.com` 相关的日志或 DNS 痕迹
- 基础持久化痕迹

其中：

- macOS 脚本会检查统一日志、`LaunchAgents`、`LaunchDaemons`
- Windows 脚本会检查 DNS 缓存、DNS 客户端日志、启动项、Run 键

## 已覆盖 IOC

当前脚本会重点搜索以下高信号字符串：

- `apifox.it.com`
- `/public/apifox-event.js`
- `/event/0/log`
- `/event/2/log`
- `af_uuid`
- `af_os`
- `af_user`
- `af_name`
- `af_apifox_user`
- `af_apifox_name`
- `_rl_headers`
- `_rl_mc`
- `collectPreInformations`
- `collectAddInformations`

说明：

- 启动项、`LaunchAgents`、`LaunchDaemons`、Run 键等检查属于补充性的启发式检查，用于发现异常残留，不代表公开分析明确披露了相同的持久化方式。

## 风险时间窗

公开事件中需要重点关注的时间窗为：

- `2026-03-04`
- `2026-03-22`

如果你在这段时间内运行过 Apifox 桌面端，即使脚本没有命中 IOC，也不应直接判定为安全。

## 快速开始

### macOS

```bash
cd /Users/espoir/Downloads/apifox
chmod +x apifox_macos_ioc_check.sh
./apifox_macos_ioc_check.sh
```

如果你希望统一日志扫描等待更久：

```bash
LOG_TIMEOUT_SECONDS=60 ./apifox_macos_ioc_check.sh
```

如果你希望调整统一日志回溯天数：

```bash
LOG_LOOKBACK_DAYS=60 ./apifox_macos_ioc_check.sh
```

### Windows

在 PowerShell 中执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\apifox_windows_ioc_check.ps1
```

如果你希望扩大 DNS 客户端日志的回溯窗口：

```powershell
.\apifox_windows_ioc_check.ps1 -LogLookbackDays 60
```

如果你希望提高 DNS 客户端日志的最大扫描事件数：

```powershell
.\apifox_windows_ioc_check.ps1 -DnsLogMaxEvents 8000
```

## 输出说明

脚本输出分为三类：

- `[INFO]`：普通信息
- `[WARN]`：需要关注，但不一定代表已受影响
- `[HIT]`：命中 IOC 或高可疑痕迹

脚本结束时会输出：

- 命中项数量
- 风险分值
- 粗粒度结论：`未发现直接 IOC`、`低风险`、`中风险`、`高风险`

## 结果怎么解读

这个项目给出的结论是“本地 IOC 检测结果”，不是最终事件定性。

即使脚本没有命中，如果满足以下任一条件，仍建议按高风险主机处理：

- 你在 `2026-03-04` 至 `2026-03-22` 期间启动过 Apifox 桌面端
- 主机上保存或使用过 SSH、Git、Kubernetes、npm、云平台、CI/CD 等敏感凭证
- 主机曾用于连接生产环境、堡垒机、代码仓库或发布系统

## 建议处置

如果命中 IOC，或者主机明确落在风险时间窗内，建议至少执行这些动作：

- 轮换该主机上使用过的 SSH 密钥、访问令牌和云平台凭证
- 审计 Git、Kubernetes、VPN、服务器、云平台和代码仓库登录日志
- 排查异常启动项、守护进程、登录项和额外后门文件
- 结合 EDR、DNS 日志、代理日志、网络边界日志进一步确认是否外联

## 局限性

- 不能替代完整取证和应急响应流程
- 只能发现当前仍存在于本机磁盘、缓存或日志中的痕迹
- 如果缓存、历史记录、日志已被清理，可能无法命中
- 如果攻击链投放了与公开 IOC 无关的二阶段载荷，本项目不一定能直接发现
- 不能代替服务端访问日志、身份凭证使用记录和网络流量审计

## 验证情况

当前已完成：

- `apifox_macos_ioc_check.sh` 的语法检查
- `apifox_macos_ioc_check.sh` 的本机实跑验证

说明：

- 当前环境没有可用的 PowerShell 运行时，因此 `apifox_windows_ioc_check.ps1` 本次未做本机执行验证
- Windows 脚本采用保守实现，兼容思路以 Windows PowerShell 5.1 和 PowerShell 7 为目标

## 文件说明

- [apifox_macos_ioc_check.sh](/Users/espoir/Downloads/apifox/apifox_macos_ioc_check.sh)：macOS 本地 IOC 检测脚本
- [apifox_windows_ioc_check.ps1](/Users/espoir/Downloads/apifox/apifox_windows_ioc_check.ps1)：Windows PowerShell 本地 IOC 检测脚本

## 使用建议

如果你准备把这个目录直接发给同事，建议同时说明两点：

- 脚本结果只能作为快速排查依据，不能替代正式取证
- 只要命中过风险时间窗，就应该优先处理凭证轮换，而不是等待更多 IOC 命中
