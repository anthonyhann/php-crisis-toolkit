# PHP2Shell 应急体检报告（模板）

- 生成时间：{generated_at}
- 主机标识：{host_label}
- 工具版本：php-crisis-toolkit {tool_version}

## 结论

受影响等级：**{risk_level}**（CRITICAL / HIGH / WARN / OK）

## 环境信息

- PHP 版本：{php_version}（分支 {branch}）
- 运行方式（SAPI）：{sapi}
- 官方修复线：{patched_floor}

## 立即行动（按优先级）

1. 升级到官方修复版本：8.5.12 / 8.4.27 / 8.3.36 / 8.2.35（或更高）。
2. 共享主机无法自助升级？直接发给服务商：

   > 您好，我的站点运行在 PHP {php_version}。2026-10-21 PHP 官方发布了两个
   > CVSS 9.2 严重漏洞的紧急修复（CVE-2026-109618 / CVE-2026-109619）。
   > 请确认贵方 PHP 运行环境的修补计划和预计完成时间。在修补完成前，
   > 我需要了解贵方是否已部署 WAF 缓解规则。

3. 修补完成前的临时缓解：部署 WAF 规则（见仓库 waf/ 目录）。
4. PHP 8.1 及更早版本没有官方修复，请制定迁移计划。

## 官方信息来源

- PHP Group 安全公告（2026-10-21，php.net）
- CERT-EU 2026-018 / 日本 IPA 安全通告（2026-10-22）
