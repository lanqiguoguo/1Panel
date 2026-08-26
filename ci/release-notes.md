# v1.10.37-lts

- 修复应用安装时后台探测 compose 命令导致面板崩溃(SIGSEGV)的问题:探测不再读取错误详情(buserr 错误渲染依赖 HTTP 中间件初始化的 i18n,后台协程中为 nil)
