# rdp-computer-use

[![build-rdputil](https://github.com/YaoSiQian/rdp-computer-use/actions/workflows/build-rdputil.yml/badge.svg)](https://github.com/YaoSiQian/rdp-computer-use/actions/workflows/build-rdputil.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**把任何可通过 RDP 访问的 Windows 机器变成 AI agent 的 computer-use 环境** ——
屏幕截图、鼠标键盘控制、剪贴板同步、文件传输、任务级 RemoteApp，
以 MCP 或 HTTP 接口暴露给 agent harness。

English documentation: [README.md](README.md)

## 为什么做这个

云上 computer-use 沙箱笨重且多是 Linux；而真实工作发生在 Windows 上。
rdp-computer-use 让 agent 通过每台 Windows 都原生支持的协议 —— RDP ——
重新连接到普通 Windows 机器，并且**目标端零安装**：除了 RDP 本身，不需要
在目标机上装任何东西。

- **观察**：像素级截图，带稳定帧检测与元数据（原始/缩放尺寸、亮度、变化统计）。
- **操作**：鼠标点击/移动、键盘文本与组合键、滚轮、分辨率调整——
  自动重连与会话保活都已处理。
- **交换**：双向剪贴板；通过 RDP 原生驱动器重定向（`\\tsclient\...`）
  推拉文件——目标端无需额外服务。
- **范围**：整张桌面，或单个 RemoteApp（RAIL）——当任务只发生在一个
  应用里时。

## 架构

```
agent harness（Claude Code / Codex / OpenCode / ZCode / 任意 MCP 客户端）
        │  MCP over stdio            HTTP REST
        ▼                            ▼
┌──────────────────────  gateway（Python）  ────────────────────┐
│  profiles · 会话池 · 截图管线 · 工具箱                         │
└──────────────────────────────┬────────────────────────────────┘
                               │ 拉起并守护
                               ▼
                      rdputil（Rust + IronRDP）
                               │ RDP（TLS/CredSSP, cliprdr, rdpdr,
                               │ rdpsnd, RAIL, display control）
                               ▼
                    Windows 目标机（XP … 11），或 xrdp
```

| 组件 | 语言 | 职责 |
| --- | --- | --- |
| `gateway/` | Python 3.10+ | MCP/HTTP 服务、会话池、观察管线 |
| `tools/rdputil/` | Rust | 常驻 RDP 客户端守护进程（输入、剪贴板、文件、RAIL） |

Rust 客户端以公开 git 源方式消费
[IronRDP](https://github.com/Devolutions/IronRDP)（原因见
`tools/rdputil/Cargo.toml` 注释）。

## 快速开始

前置条件：Rust 工具链（1.85+）、Python 3.10+，以及一台开启了 RDP、
有可登录账号的目标机。

```bash
git clone https://github.com/YaoSiQian/rdp-computer-use.git
cd rdp-computer-use

# 1. 编译客户端守护进程（首次编译需要几分钟）
cargo build --release --manifest-path tools/rdputil/Cargo.toml

# 2. 安装 gateway 依赖
pip install -r requirements.txt

# 3. 配置目标机（此文件永不提交）
cp gateway/profiles.sample.json gateway/profiles.json
```

编辑 `gateway/profiles.json`：

```json
{
  "profiles": {
    "mypc": {
      "host": "203.0.113.10",
      "username": "operator",
      "password_env": "MYPC_PASS",
      "rdpdr": true,
      "display_control": true
    }
  }
}
```

密码从 `password_env` 指定的环境变量读取：

```bash
export MYPC_PASS='...'
python -m gateway --mcp --profile mypc
```

条目也可以直接导入 `.rdp` 文件（`"rdp_file": "path/to/file.rdp"`），
无需重复填写 host/username——见 [docs/USAGE.md](docs/USAGE.md) 第 3.1 节。

## 接入 agent harness

gateway 是标准 MCP stdio 服务，任何支持 MCP 的 harness 都能直接接入。
启动命令（在仓库目录下执行；harness 配置里建议写绝对路径）：

```
python -m gateway --mcp --profile mypc
```

| Harness | 配置位置 |
| --- | --- |
| Claude Code / ZCode | 设置里的 `mcpServers`，或安装自带 skill（见下） |
| Codex CLI | `config.toml` 的 `mcp_servers` |
| OpenCode | `opencode.json` 的 `mcp` 段 |
| 其他 MCP 客户端 | `python -m gateway --mcp --profile <name>`（stdio） |

**Agent skill**：[`skills/rdp-computer-use/SKILL.md`](skills/rdp-computer-use/SKILL.md)
教 agent 掌握操作闭环（观察 → 操作 → 确认、文件传输、RemoteApp 生命周期、
错误恢复）。把它复制或软链到 harness 的 skill 目录（例如
`~/.claude/skills/rdp-computer-use/`）；读取 `AGENTS.md` 的 harness
会自动找到它和使用手册。

## HTTP 模式

```bash
python -m gateway --http --port 8080
# POST /vm/mypc/screenshot · /click · /type · /key · /clipboard
# POST /vm/mypc/file_push · /file_pull · /app/start · /probe
# GET  /vm/mypc/state · /vm/mypc/screenshot/png
```

完整端点与工具参考：[docs/USAGE.md](docs/USAGE.md)。

## 平台支持

| | 状态 |
| --- | --- |
| Windows 客户端（编译+运行） | 已支持，每次 push 都有 CI 构建 |
| 服务端目标 | Windows（XP → 11）走 RDP；xrdp 走 `oneshot` 引擎 |
| Linux/macOS 客户端 | 计划中 —— 输入/剪贴板栈可移植，驱动器重定向需要 nix rdpdr 后端 |

预编译 Windows 二进制附带在每次 release 与
[Actions](https://github.com/YaoSiQian/rdp-computer-use/actions)
页面的产物里（artifact 名 `rdputil-windows-x64`）。

## 安全说明

- gateway 只在内存中持有 RDP 凭据；profile 通过环境变量引用密码，
  `gateway/profiles.json`、`runs*/`、`experiments/` 均已 gitignore。
- 任何 RDP 登录都意味着对目标机的完全控制——请使用专用账号，
  并只自动化你被授权操作的机器。
- 客户端会保活并自动重连；注意在单会话 RDP 配置的目标机上，
  连接会踢掉交互式控制台会话。

## 许可证

[MIT](LICENSE)
