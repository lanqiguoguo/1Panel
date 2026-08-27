# v1.10.36-lts

- 应用启停/安装/卸载的 compose 调用兼容两种形态:现代 Docker 自带的 v2 插件(`docker compose`)与旧版独立二进制(`docker-compose`),自动探测、进程内缓存,无需用户调整 Docker 安装
- 修复卸载应用时因缺少 compose 命令导致的失败
