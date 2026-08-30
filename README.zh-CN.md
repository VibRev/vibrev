# vibrev

[English](README.md) | 简体中文

VibRev 逆向 MCP 引擎的共享运行时,以及把它们接进 MCP 客户端的安装器。

这个仓库有两件看起来无关、实际上分不开的活:

- **四个库 crate**,三个引擎以 path 依赖引入,让三个各自开发的 MCP server 呈现同一个面。
- **一个二进制 `vibrev`**,在你机器上找到这些引擎,并把它们写进 Claude Code / Cursor / VS Code / Codex。

它们必须在一起,因为真正难缠的 bug 长在两者之间:一个由安装器写、由引擎读的 token 文件;一份由引擎打印、由安装器解析的 `skills list --json`。两个程序谁也看不见对方的源码。**凡是两个 VibRev 程序必须达成一致的东西,都收在这里,而且只有一份类型。**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## 各 crate

| Crate | 类型 | 是什么 |
|---|---|---|
| [`vibrev`](crates/vibrev) | bin | 安装器与派发器。发现引擎二进制、写客户端配置、exec 进引擎 CLI。不链接任何引擎代码。 |
| [`vibrev-kit`](crates/vibrev-kit) | lib | 引擎共享运行时:CLI 构建、schema 规范化、工具策略、分页、输出限流、后台任务、HTTP 传输。 |
| [`vibrev-tool-macros`](crates/vibrev-tool-macros) | proc-macro | `#[vibrev_tool]` / `#[vibrev_tool_router]` —— 一份定义同时驱动 MCP 工具面和 clap 命令树。 |
| [`vibrev-skills`](crates/vibrev-skills) | lib | 编进引擎二进制的 agent skill:归档格式、打包器,以及两端共用的两个 CLI 动词。 |
| [`toy-engine`](crates/toy-engine) | bin | 参照引擎。共享 crate 在**本仓库内**的第二个消费方。 |

## `vibrev` 命令面

```bash
vibrev doctor                      # 装了什么、在哪、什么版本
vibrev install --all               # 为找到的每个引擎写 MCP 条目（默认 project + HTTP，连 skill）
vibrev install ida --mode stdio    # 客户端拉起二进制，不连监听面
vibrev install ida --scope global --client claude-code
vibrev list                        # 哪些客户端当前持有 vibrev 条目
vibrev uninstall                   # 不点名引擎 = 移除所有 vibrev-* 条目
vibrev skill list                  # 每个引擎提供哪些 skill、本地是什么状态
vibrev token rotate                # 轮换 HTTP bearer token,并改写已装的 HTTP 配置
vibrev ida decompile main --limit 20   # 认不出来的参数原样交给引擎
```

`--json` 是全局的:人类模式把 `Error: <msg>` 写 stderr、退出码 1;`--json` 把 `{"ok":false,…}` 写 stdout、退出码 1——调用方只解析一条流。

`doctor` 永远退出 0。它只报告,不裁决。

### 引擎

| id | 二进制 | 领域 |
|---|---|---|
| `ida` | `ida-headless-mcp` | IDA Pro |
| `bn` | `bn-headless-mcp` | Binary Ninja |
| `jadx` | `rjadx` | Android APK / DEX |

发现分四级,先命中先赢,**第一级不向下回落**:

1. `~/.vibrev/config.toml` 里的 `[engines.<id>] path`
2. `~/.vibrev/engines/<bin>`
3. `PATH`
4. 都没有 —— 打印该引擎的安装指引

根目录是 `~/.vibrev`,可用 `VIBREV_HOME` 覆盖。安装器和引擎走**同一份**解析代码,所以设了这个变量两边一起动。

### 客户端

| id | 客户端 | 全局文件 | 项目文件 | 格式 |
|---|---|---|---|---|
| `claude-code` | Claude Code | `~/.claude.json` | `./.mcp.json` | JSON |
| `cursor` | Cursor | `~/.cursor/mcp.json` | `./.cursor/mcp.json` | JSON |
| `vscode` | VS Code | `<config>/Code/User/mcp.json` | `./.vscode/mcp.json` | JSONC |
| `vscode-insiders` | VS Code Insiders | `<config>/Code - Insiders/User/mcp.json` | `./.vscode/mcp.json` | JSONC |
| `codex` | Codex | `~/.codex/config.toml` | `./.codex/config.toml` | TOML |
| `claude-desktop` | Claude Desktop | `<config>/Claude/claude_desktop_config.json` | — | JSON |
| `windsurf` | Windsurf | `~/.codeium/windsurf/mcp_config.json` | `./.windsurf/mcp.json` | JSON |
| `zed` | Zed | `<config>/Zed/settings.json` | `./.zed/settings.json` | JSONC |
| `cline` | Cline | VS Code `globalStorage` | — | JSON |
| `roo` | Roo Code | VS Code `globalStorage` | — | JSON |
| `kilo` | Kilo Code | VS Code `globalStorage` | — | JSON |
| `lmstudio` | LM Studio | `~/.lmstudio/mcp.json` | — | JSON |
| `gemini` | Gemini CLI | `~/.gemini/settings.json` | — | JSONC |
| `qwen` | Qwen Coder | `~/.qwen/settings.json` | — | JSONC |
| `copilot` | Copilot CLI | `~/.copilot/mcp-config.json` | — | JSON |
| `amazonq` | Amazon Q | `~/.aws/amazonq/mcp_config.json` | — | JSON |
| `warp` | Warp | `~/.warp/mcp_config.json` | — | JSON |
| `kiro` | Kiro | `~/.kiro/mcp_config.json` | — | JSON |
| `trae` | Trae | `~/.trae/mcp_config.json` | — | JSON |
| `crush` | Crush | `~/crush.json` | — | JSON |

`--client` 也认别名（`roocode`、`amazon-q`、`vs-code-insiders` 等）。没有 project 文件的客户端在 `--scope project` 下会被跳过。不带 `--client` 时仍然只写看起来已安装的客户端。

改写是**保形**的:`serde_json` 走一圈会把 VS Code `mcp.json` 里的注释全删掉,所以 JSONC 和 TOML 分别走 `jsonc-parser` 与 `toml_edit`。写入是原子的(临时文件 + rename)、带建议锁,并留一份 0600 的一次性 `.bak`。

`install` 默认是 **project** 作用域和 **`--mode http`**。IDA 和 BN 得到一个 URL，由你自己启动的进程来应答；`--mode stdio` 改成客户端拉起二进制。bearer 默认只从 `~/.vibrev/token` 抄进**全局** HTTP 配置（项目级文件会进 git）。`--with-token` 连 project 一起写；`--no-token` 全局也不写。监听面本身不能关鉴权，条目里没有 Authorization 的客户端会 401：

```jsonc
"vibrev-ida": {
  "type": "http",
  "url": "http://127.0.0.1:8765/mcp",
  "headers": { "Authorization": "Bearer vbr_…" }
}
```

jadx 没有监听端口，仍然是客户端拉起的 stdio：

```jsonc
"vibrev-jadx": { "command": "~/.vibrev/engines/rjadx", "args": ["mcp", "--stdio"] }
```

HTTP 引擎要自己启动（`ida-headless-mcp` / `bn-headless-mcp`）；默认绑 `127.0.0.1:8765`。

几个 flag 值得知道:

- `--delegate` 把写入交给客户端自己的 CLI(`claude` / `codex` / `code`)而不是直接改文件。**默认关闭**,因为它有损:`codex mcp add` 会把 `~/.codex/config.toml` 重新序列化,抹掉 `[mcp_servers]` 段里的注释。
- `--no-skills` 只写 MCP 条目。skill 装到 `~/.claude/skills`,只有 Claude Code 会读;没有 `.vibrev-skill.json` 标记的目录既不覆盖也不删除。
- `--mode http|stdio` 选择传输。HTTP 是默认；没有监听面的引擎（jadx）两种都写 stdio。
- `--with-token` / `--no-token` 覆盖「project 不写 bearer、global 写」这条默认。两者互斥，也和 `--mode stdio` 互斥。
- `--scope global` 写本机全局文件。默认是 project。

## `vibrev-kit`

收纳标准是**「两个 VibRev 程序必须达成一致的东西」**,而不只是「引擎之间共享的」。这就是 `token` 在这里的原因:安装器不是引擎,但它打开同一个文件。

| 模块 | 职责 |
|---|---|
| `cli` | JSON Schema → `clap::Command`,以及 `ArgMatches` → 工具入参。白名单分类器:映射不了的构造会被**报告**,而不是静默丢弃。 |
| `contract` | 把跨引擎的工具面契约做成**能跑的东西**。扫描目录,报出每一处走样。机制在这里,各引擎的名单由外面传入。 |
| `decorate` | rmcp 全部 `ServerHandler` 方法的唯一镜像。`Decorator` 的每个方法默认就是转发,所以装饰器不可能静默地把一个它没听说过的能力弄下线。 |
| `output` | 答案太大时的兜底网:保形预览 + 私有落盘,记账写在 `_meta.vibrev`。 |
| `page` | 分页算术的唯一定义——会真正前进的 offset、会钳制的 limit。 |
| `policy` | 用户要更少工具时,引擎该发哪些。默认全给,flag 只做减法。只读模式由 `readOnlyHint` 派生,不靠手维护的名单。 |
| `render` | 工具结果 → 可读文本。记账字段靠**结构**识别,不靠字段名清单。 |
| `schema` | 每个面都要讲的那套 JSON Schema 词汇。读的一半和改写的一半互相咬合。规范化发生在 `Tool` **构造时**,不是服务时。 |
| `session` | 工具调用唯一无法从自身 schema 得到的值:在哪个会话/数据库上干活。建模的是**槽位**,不是生命周期。 |
| `tasks` | 后台任务与 MCP Tasks 面。只交注册表和协议适配;**哪个**调用走后台是引擎自己的决定。 |
| `token` | 共享的 HTTP bearer token 文件 `~/.vibrev/token`。**每一行都接受**,这正是轮换被打断也不掉线的原因。用 `O_EXCL` 以 0600 创建——绝不先建后 chmod。 |
| `transport` | **仅 `http` feature。** 引擎摆在 MCP server 前面的 HTTP 监听器。 |

crate 根上还有:`ToolOutcome`、`Rendered<T>`(既保住 `structuredContent`,又把可读文本放进 `content`)、`ToolDef`、`Advertised`、`engine_identity!`,以及 `parse_int` / `parse_unsigned`(认 `184`、`0xb8`、`0b1011`)。

### `http` feature

默认关闭。只走 stdio 的引擎——以及根本不讲协议的安装器——不该为了拿 `schema` 和 `policy` 去编 axum。

```toml
vibrev-kit = { version = "0.0.1", features = ["http"] }
```

`Listener::serve` 接收引擎的 `axum::Router`,把 bearer 闸门 layer 在**整个** router 上。引擎从来没有机会说哪些路由豁免,`AccessPolicy.auth` 也不是 `Option`。**没有办法起一个不鉴权的监听面。** 凭据失败回 401 + `WWW-Authenticate`。

## `vibrev-tool-macros`

`#[vibrev_tool_router]` 把块里每个 `#[vibrev_tool]` 改写成 `#[rmcp::tool]`,转交 `#[rmcp::tool_router]`,同时产出 CLI 构建器——**在同一个编译单元里**,所以 MCP 面和 CLI 不可能漂移。

```rust
#[vibrev_tool_router(group_about(binary = "Inspect mapped functions"))]
impl Toy {
    /// Liveness probe; returns the engine identity.
    #[vibrev_tool(verb = "ping", title = "Engine heartbeat",
                  annotations(read_only = true, idempotent = true))]
    pub async fn ping(&self) -> Result<Rendered<Pong>, ErrorData> { … }

    #[vibrev_tool(verb = "decompile", title = "Decompile function",
                  annotations(read_only = true, idempotent = true),
                  cli(positional = "func"))]
    pub async fn decompile(&self, Parameters(a): Parameters<DecompileArgs>)
        -> Result<Rendered<Decompiled>, ErrorData> { … }
}
```

`title` 和 `annotations(read_only = …)` 都是**必填**,缺了各是一条编译错误。正是这一点让 `policy` 能**派生**只读模式,而不必维护一份 deny list。

在 impl 块上生成:`vibrev_tool_defs()`、`vibrev_cli(bin)`、`vibrev_call(name, args)`、`try_vibrev_call(…)`。CLI 那条路通过 MCP router 用的同一个转换,进到同一批函数体。

## `vibrev-skills`

引擎把自己的参考文档编进自己的二进制,按需导出。三行:

```text
build.rs        vibrev_skills::pack::pack(&root)?   -> OUT_DIR
src/skills.rs   vibrev_skills::embedded!()          -> Embedded
main.rs         args.run(&SKILLS, name, version)    -> `skills list` / `skills export`
```

这个 crate 沿一条 feature 劈开,好让构建脚本不必为运行时付钱:

```toml
[dependencies]       vibrev-skills = { path = "…" }                          # 读取 + 两个动词
[build-dependencies] vibrev-skills = { path = "…", default-features = false } # 只有打包器和 flate2
```

没有那一行,构建脚本就要**为了读几个 Markdown 而链接一个 MCP server 库**——`vibrev-kit` 会拖进 rmcp、tokio 和 schemars。这和 `vibrev-kit` 给 axum 划的是同一条线。

打包器只走一遍目录、名字排序,所以归档在不同机器上**逐字节相同**。安装器要读的每个字段都是 `#[serde(default)]`:一个比安装器更老、只回 `{}` 的引擎报告的是「没有 skill」而不是「格式错」,`vibrev install --all` 继续走。

## 构建与测试

Edition 2024,MSRV **1.95**,resolver 3。这里没有任何东西链接反汇编器 SDK,普通 checkout 就能构建。

```bash
cargo test --workspace --all-features
```

**`--all-features` 不是可选的。** `vibrev-kit` 的 `http` feature 默认关闭,不带它 `transport` 的测试**一条都不编译**——而 `cargo test -p vibrev-kit` 照样打印一行绿。`toy-engine` 也必须在工作区里跑:它的契约扫描跑的是真实的宏派生 catalog,不是手搭的 fixture。

下面这条是**定期跑,不是合入门禁**——它驱动真实客户端 CLI 去动你真实的配置文件:

```bash
cargo test -p vibrev --test real_clients -- --ignored --nocapture
```

golden 文件在 `crates/vibrev/tests/golden/`,用 `UPDATE_GOLDEN=1 cargo test` 刷新。

## 与引擎的关系

`vibrev` 这个二进制不链接引擎代码,也不在请求路径上。Unix 下派发是真正的 `execvp`:不 fork、不留 supervisor,信号、作业控制、退出码、终端归属天然是引擎的,不需要任何东西转发。

**库** crate 则是另一回事。引擎依赖 `vibrev-kit` 与 `vibrev-tool-macros`(带 skill 的还依赖 `vibrev-skills`),它们最终被编进引擎的请求路径。所以**改这里能弄坏一个不在本仓库的程序,而本仓库的构建不会有任何东西发现**。

对冲它的是 `contract`。它把跨引擎的工具面约定变成一次**扫描**:引擎在自己的测试里对自己的目录跑一遍,于是一次改动了 schema 形状、标题或工具顺序的 kit 变更,会在那里红,而不是在某个用户的客户端里。各引擎把自己的名单传进来,kit 只持有机制、从不持有某个引擎的工具名。扫描不碰反汇编器、**不需要 license**——它的目录完全从 `#[vibrev_tool]` 属性构建。

有两个文件是「互相看不见源码的程序之间的合同」,所以它们是共享 crate 里的**类型**,而不是注释里的一段话:

- `~/.vibrev/token` —— `vibrev token rotate` 写它,每个引擎的监听面读它。一份实现:`vibrev_kit::token`。
- `<engine> skills list --json` —— 引擎打印它,`vibrev install` 解析它。一个类型:`vibrev_skills::Listing`。

## 许可

Apache License 2.0 —— 见 [LICENSE](LICENSE)。
