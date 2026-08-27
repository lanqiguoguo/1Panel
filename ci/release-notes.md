# v1.10.37-lts

## 修复与优化

- **修复应用安装崩溃（关键）**：compose 探测不再对 nil error 调用 `Error()`（原会导致 SIGSEGV）；后台 goroutine（cron/安装/升级）调用 buserr 错误渲染时不再因缺少 HTTP i18n localizer 崩溃
- **修复应用商店已安装应用日志不显示**：日志/编排/运行时操作统一走 compose 双形态探测（`docker compose` v2 插件与 `docker-compose` 独立二进制自动适配），容器页与商店页日志一致
- **应用商店同步性能优化**：图标与 compose 下载改为 8 并发 + 未变化图标跳过，同步耗时从约 1分50秒 降至约 5 秒
- **安全加固**：
  - WebSocket（SSH 终端/容器 exec/文件操作）拒绝跨站 Origin
  - chown/chmod 命令注入防护（用户/组白名单 + 路径校验）
  - 上传文件名净化（路径穿越）+ 512MB 大小限制
  - 解压路径穿越/zip 炸弹防护（条目与总量限制）
  - 删除/回收站保护系统目录与面板数据目录
  - `/api/v1/images` 不再匿名暴露 uploads 目录
  - 设置接口不再回显 MFA 密钥与代理密码明文
  - 全局 panic recovery + 生产环境 Release 模式
  - 登录会话固定修复（登录下发新 session）+ 会话 LoggedIn 标记
  - MFA 登录限速（连续失败 5 次锁定 30 分钟）+ 验证码强度提升
  - Cookie SameSite=Lax（CSRF 防护）
  - `/settings/update` key 白名单
  - CIDR 白名单判断 O(1)（修复 /8 网段遍历 DoS）
  - Docker client 泄漏修复 + 镜像推送 use-after-close 修复
  - 版本比较等值误判修复
  - 登录密码不再明文回退（RSA 公钥缺失时阻止提交）
  - Wget 下载 SSRF 防护 + 大小限制 + 超时
  - 前端依赖安全漏洞清零（echarts 6.1.0 / element-plus 2.14.3 / markdown 链）
- **其他修复**：
  - 回收站重复显示修复（bind mount 同目录去重）
  - 命令超时彻底杀死进程组（无孤儿进程）
  - 应用升级/重建状态竞态修复（条件写回）
  - 下载文件同步完成（不再异步返回未写完文件）
  - favicon 标题栏显示修复
  - 数据库页面空态崩溃修复
