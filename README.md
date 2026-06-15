# CTF Compass

CTF Compass 是一个本地优先的 CTF 桌面工作台。它把题面、附件、Web 靶机、CTF2 题库导入、自动分析、flag 候选和报告导出放在同一个应用里。

它只面向合法 CTF / 本地靶机 / 已授权比赛靶机，不用于真实未授权目标。

## 下载

到 GitHub Releases 下载最新版：

```text
CTF Compass v0.9.2
CTF-Compass-0.9.2-win-x64.zip
```

如果 Release 资产暂时不可见，可以到最新 Actions run 底部下载 artifact：

```text
CTF-Compass-v0.9.2-windows
```

## 主要功能

- 本地附件分析：文本、图片、压缩包、ELF/PE/APK、pcap/pcapng、PDF/Office、WAV、MP4、磁盘镜像、内存转储等。
- 递归处理：自动解包、提取字符串、识别编码层、扫描常见 flag 样式和派生文件。
- Web 靶机分析：仅限已授权目标，默认同源 GET、限量扫描，不提交表单，不自动攻击。
- CTF2 连接器：浏览 BUUCTF 公开题库、诊断连接、导入附件、同步到工作台并自动求解。
- 证据与报告：保存人工观察、候选 flag、分析过程，并导出 Markdown 报告。
- 沙盒目录：自动生成物、CTF2 下载缓存和会话文件统一放在应用沙盒中。

## CTF2 使用方式

1. 打开左侧 `CTF2`。
2. 先点 `刷新`，公开题库不需要登录也能浏览。
3. 下载附件前需要登录。优先使用 `浏览器登录`，登录后从 CTF2 页面的 Local Storage 复制 token。
4. 把 token 粘贴到 `浏览器 token` 区域，点 `验证并连接`。
5. 选择有附件的题目，点 `导入并求解`。
6. 导入后附件会进入工作台，并自动触发本地分析。

如果连接失败，点 `诊断`，再点 `复制日志`，把日志发出来即可判断是 token、接口还是本地沙盒问题。

CTF2 靶机启动和 flag 提交仍需手动在 CTF2 页面确认，应用不会自动启动靶机或提交 flag。

## Web 页面使用方式

Web 页面只做有边界的 CTF 靶机线索扫描。填写目标地址，勾选授权确认，再开始分析。默认策略：

```text
仅 GET
同源范围
不执行 JS
不提交表单
限时限量
```

公网 CTF 靶机需要额外勾选允许公网目标。

## 设置页

设置页保留少量高频管理项：

- 切换主题。
- 查看运行版本和沙盒路径。
- 打开或清理沙盒。
- 管理 CTF2：查看登录状态、导入记录、打开 CTF2 下载目录、清理 CTF2 下载缓存。
- 检查 GitHub Release 更新。

## 本地开发

```powershell
npm install
npm run dev:electron
```

创建 Windows ZIP：

```powershell
npm run dist:zip
```

运行 smoke test：

```powershell
npm run smoke:desktop
npm run smoke:analyzer
npm run smoke:web
```

## 目录结构

```text
desktop/                  Electron 桌面端
  main.js                 主进程、IPC、沙盒、Release 检查
  preload.js              renderer 安全 API
  ctf2-connector.js       CTF2 登录、题库、附件下载
  renderer/               页面、样式、前端逻辑
scripts/                  smoke test 和构建辅助脚本
docs/                     方法论和设计文档
```

## 发布

当前正式版通过 `.github/workflows/release-preview.yml` 自动发布到：

```text
CTF Compass v0.9.2
```

发布前会运行桌面壳、分析器和 Web 分析 smoke test。测试失败不会发布 Release。
