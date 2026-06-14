# 黄鹤杯赛前准备

本文根据公开的黄鹤杯赛后题解和 2026 赛事公开方向整理，用于赛前检查 CTF Compass 的覆盖范围。只使用公开资料，不包含进行中比赛的未公开答案。

## 公开题型观察

2025 公开线上赛题解中出现过：

- Misc：PNG 宽高异常、图片尾部压缩包、USB 键盘流量、压缩包处理、Base58/ROT13、UTF-16 宽字符。
- Pwn：自定义 VM、动态 seccomp、负索引、MIPS、RWX 内存、栈溢出与 ORW。
- Crypto：RSA 参数恢复、非标准指数处理、栅栏密码。
- 日志与取证：日志时间线、流量和附件关联分析。

2026 公开赛事方向还包含 AI 安全、模型逆向、提示词注入、工业互联网与智能网联汽车等场景。

## CTF Compass 当前专项覆盖

| 方向 | 自动化能力 | 当前边界 |
| --- | --- | --- |
| USB 流量 | 识别 USBPcap/usbmon 链路，恢复标准 HID 键盘输入，导出鼠标轨迹 CSV | 非标准 HID 报告描述符和复合设备可能需要 Wireshark/TShark 手工校验 |
| PNG 异常 | 根据 IDAT 解压后的扫描线结构推断被修改的 IHDR 宽高，生成修复候选并递归检查 | Adam7 隔行 PNG 和自定义像素重排需要人工处理 |
| 图片/压缩包 | 尾部文件、ZIP/GZIP/TAR/TGZ、文本块、LSB、GIF 位流、JPEG 段/F5/DCT | ZIP ZipCrypto 已知明文攻击仍建议使用 bkcrack |
| 宽字符/编码 | UTF-16 strings、Base58、ROT13、栅栏、Morse、Polybius、Brainfuck/Ook 等 | 强密码学和题目自定义编码仍需按题面推导 |
| Pwn | ELF checksec-lite、危险函数、seccomp/alarm 导入、RWX/可写区、ROP/ORW/ret2win 路径 | 不会自动攻击远程服务；VM 指令语义和实际利用仍需人工逆向 |
| AI/模型逆向 | 安全识别 ONNX/Safetensors/Pickle/Joblib/Checkpoint，提取元数据、张量、算子、提示词和危险反序列化线索 | 不执行 Pickle 或模型；对抗样本和复杂模型逻辑需要专用环境 |

## 比赛导入顺序

1. 将题目附件全部一次性加入工作台，先运行自动求解。
2. 优先查看已生成文件：USB 键盘文本、鼠标 CSV、PNG 修复候选、解包文件、模型报告和 Pwn 报告。
3. 对 `partial` 结果先确认失败动作指南，再决定使用 Wireshark、bkcrack、GDB、Ghidra 或题目指定环境。
4. Pwn 先确认架构、保护、I/O 模型、seccomp/RWX 和提供的 libc/loader，再编写利用。
5. 不在主机直接执行未知 Pickle、模型、脚本或二进制；使用比赛隔离环境。

## 公开参考

- 2025 黄鹤杯线上赛公开题解：https://www.cnblogs.com/DSchenzi/p/19115001
- 2025 黄鹤杯 Pwn 公开题解：https://blog.csdn.net/2301_79909304/article/details/152500682
- 2026 黄鹤杯公开赛事方向：https://pan.eduyun.cn/competition/huanghebei.html
