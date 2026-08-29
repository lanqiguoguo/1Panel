# 1Panel 前后端代码审查报告

审查日期：2026-08-29  
审查范围：`backend/`、`frontend/src/`、路由/API、安装及部署脚本  
审查方式：静态代码审查；由 `gpt-5.6-luna`（max reasoning）并行审查后由主代理核验关键证据。

## Findings

### P1 / 高危

1. **归档安全校验失败后回退到未校验 Shell 解压，可任意路径写入。**
   - [backend/utils/files/file_op.go:702](/home/1Panel/backend/utils/files/file_op.go:702) 的 SDK 路径检查 `..`、绝对路径和符号链接；[file_op.go:801](/home/1Panel/backend/utils/files/file_op.go:801) 在 SDK 任意错误后仍调用 Shell archiver。
   - [tar_gz.go:21](/home/1Panel/backend/utils/files/tar_gz.go:21)、[zip.go:23](/home/1Panel/backend/utils/files/zip.go:23)、[tar.go:23](/home/1Panel/backend/utils/files/tar.go:23) 未检查归档成员路径。
   - 已认证用户提交含 `../` 或 symlink 的有效归档即可触发。面板以高权限运行时可覆盖目标目录外文件。
   - 修复：安全校验错误不得 fallback；统一使用带成员路径、链接和大小限制的解压器。

2. **备份恢复直接执行未校验的 `tar` Shell 命令。**
   - [backend/app/service/cronjob_helper.go:246](/home/1Panel/backend/app/service/cronjob_helper.go:246) 的 `handleUnTar` 在 253-260 行拼接路径执行 `openssl | tar` 或 `tar zxvfC`。
   - 被网站、应用、运行时、数据库及快照恢复调用。恶意归档可目录穿越或通过 symlink 写入；路径元字符还带来命令注入风险。
   - 修复：统一安全解压，使用 `exec.Command` 参数数组，拒绝绝对路径、`..`、symlink/hardlink。

3. **安装后管理员密码写入全局可执行脚本。**
   - [install.sh:470-480](/home/1Panel/install.sh:470) 将 `PANEL_PASSWORD` 写入 `ORIGINAL_PASSWORD`；模板见 [ci/resources/1pctl:7-13](/home/1Panel/ci/resources/1pctl:7)。安装后脚本通常为 0755，本地普通用户可读取密码并接管面板。
   - 修复：不持久化密码；使用 root-only 0600 secret 或受限 IPC，至少将脚本设为 root:root 0700。

### P2 / 中危

4. **日志接口的 `req.Name` 可逃逸日志目录读取任意文件。** [file.go:481](/home/1Panel/backend/app/service/file.go:481)、493-495、524-531 将用户输入拼入 `path.Join`；`..` 会被规范化。应限制 basename 并验证最终路径。

5. **下载打开失败后未返回，可能 panic。** [file.go:544](/home/1Panel/backend/app/api/v1/file.go:544) 写错误后仍执行 `file.Close`/`file.Stat`。应立即 `return` 并检查 `Stat`。

6. **Range 解析缺少格式和边界校验。** [file.go:597](/home/1Panel/backend/app/api/v1/file.go:597)-610 直接索引 split 结果并忽略 `ParseInt` 错误；畸形 Range 可触发请求级 panic。非法范围应返回 416。

7. **批量权限修改失败后仍返回成功。** [file.go:884](/home/1Panel/backend/app/api/v1/file.go:884)-892 错误响应后没有 `return`，随后始终返回成功。

8. **HTTP 响应体未始终关闭。** [request.go:106](/home/1Panel/backend/utils/http/request.go:106)-113 在非 200 或读取失败分支泄漏 `resp.Body`，高频出站请求可能耗尽连接/文件描述符。

9. **Docker 代理密码写入 `daemon.json` 明文 URL（部署相关）。** [docker.go:703](/home/1Panel/backend/app/service/docker.go:703)-723 将解密密码写入代理配置；Docker/运维用户及备份诊断流程可能读取。应使用受保护凭据机制。

10. **MFA 登录异常后状态永久锁死。** [login-form.vue:380](/home/1Panel/frontend/src/views/login/components/login-form.vue:380)-405 设置 `isLoggingIn` 后无 `finally`；API reject 见 [api/index.ts:125](/home/1Panel/frontend/src/api/index.ts:125)-127。网络/500 后只能刷新页面。

11. **登录组件未卸载全局键盘处理器。** [login-form.vue:441](/home/1Panel/frontend/src/views/login/components/login-form.vue:441)-462 设置 `document.onkeydown` 无清理，组件离开后仍可能用闭包中的密码状态触发登录。

12. **开发服务器固定监听 `0.0.0.0`。** [vite.config.ts:39](/home/1Panel/frontend/vite.config.ts:39)-49。误在生产主机运行开发模式时，局域网可访问源码/HMR/开发代理。该项是条件性部署风险，后端 API 仍有 SessionAuth。

### P3 / 低危

13. **路由守卫信任可篡改 localStorage。** [router.ts:19](/home/1Panel/frontend/src/routers/router.ts:19)-25 仅检查持久化的 `isLogin`，且 [router.ts:40](/home/1Panel/frontend/src/routers/router.ts:40)-41 两个分支均 `next()`。可伪造登录状态加载受保护页面壳；未发现由此绕过后端 API 授权。

14. **安装日志短时写入明文密码。** [install.sh:31](/home/1Panel/install.sh:31)、[install.sh:47-50](/home/1Panel/install.sh:47) 和 [install.sh:560-566](/home/1Panel/install.sh:560) 先记录后覆盖；普通用户可在覆盖前读取。日志应使用 0600 且永不输出密码。

15. **Docker 安装脚本存在固定 `/tmp/get-docker.sh` TOCTOU。** [install.sh:425](/home/1Panel/install.sh:425)、[install.sh:435-437](/home/1Panel/install.sh:435) 下载后以 root 执行固定路径文件。本地攻击者可竞态替换。应使用 0700 临时目录、0600 文件、签名/digest 校验。

16. **MCP Compose 使用可变 `latest` 标签。** [cmd/server/mcp/compose.yml:3](/home/1Panel/cmd/server/mcp/compose.yml:3)，更新时可能执行未经验证的新镜像。应固定 digest 并验证签名。

## 验证记录

- `go version`: `go1.24.1 linux/amd64`
- `go test ./backend/...`: **通过**，所有有测试的包均 `ok`，其余包显示 `[no test files]`。
- 前端 `npm run build:pro`：**通过**（Vite 7.3.6，4905 个模块，约 2 分 14 秒），产物写入 `cmd/server/web`。构建警告：`.env` 中的 `NODE_ENV=production` 不被 Vite 支持；部分压缩后 chunk 超过 500 kB。此前 `build:test` 的 `vue-tsc` 类型检查仍会报告大量现存错误，但生产构建脚本本身成功。
- `npm audit`：审查代理报告为 0 项漏洞；`govulncheck` 因无法访问 `proxy.golang.org` 未完成。
- 通过测试不代表上述归档、路径、权限和异常边界已有覆盖；建议优先为 P1/P2 增加回归测试。
