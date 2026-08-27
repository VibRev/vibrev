# vibrev 执行清单

> 本仓库的当前工作。只写还没做完的。
> 两重身份:引擎依赖的共享 crate(`vibrev-tool-macros` + `vibrev-kit` + `vibrev-skills`),以及安装/派发 CLI。
>
> **二进制不链接引擎库、不在请求路径上;但 `vibrev-kit` 在**——它是 `ida-headless-mcp` 与 `bn-headless-mcp` 请求路径里的 path 依赖。见「代价」。

---

## 现状

共享化已收口。`vibrev-kit` 今天交出:`cli`(CLI 渲染器)、`schema`(规范化)、`policy`(工具策略)、`token`、`transport`(HTTP 起停样板)、`output`(输出限流)、`page`(游标分页)、`tasks`(后台任务)、`session`、`render`、`decorate`、`contract`(跨引擎契约扫描)。`vibrev-skills` 是独立 crate,因为 build.rs 要调打包器而 kit 拖着 rmcp/tokio。

**MCP 面还欠 `batch` 与 `错误语义` 两项**,两项都还没有第二个消费方,按本文件「明确不建」的同一条标准不动。

`cargo test --workspace --all-features` 合入时绿(387 passed / 0 failed),`cargo fmt --check` 通过。

---

## 当前待办

### 1. MSRV 核实(唯一一条「先量,再决定」而没量的)

| | 声明 |
|---|---|
| workspace(kit / skills / macros / vibrev / toy) | `1.95` |
| `bn-headless-mcp` | `1.91.1`(edition 2021,跟 `binaryninja` 走) |
| 本机 rustc | `1.95.0` |

cargo 按活动工具链核对每个包,所以 BN 实际上已经必须用 ≥1.95 构建,**它自己声明的 MSRV 已被 kit 传递性作废**。本机版本恰好相等,所以这件事一直没暴露。每加一个 kit 模块这条就更硬——要么降 kit 的声明,要么改 BN 的。**先量,再决定,不要顺手改。**

### 2. `OutputCache::spills()` 零消费方

兜底网的阈值必须**高于**工具的正常输出,否则它替换答案而不是接住意外(这条是 `jadx-headless-mcp` 实测撞出来的:`max_bytes` 默认 65536 而阈值 50,000 字符,一次普通的「取这个类的源码」就掉进网里)。`spills()` 是为此留的检验口——引擎可以在自己的测试里断言「一次有代表性的调用不触发兜底网」。

**实测:只有 kit 自己的两条测试在用,IDA / BN / toy-engine 一个都没断言。** 那条教训目前只活在模块文档里。

### 3. `ida tool <name>` 不受策略约束(跨引擎不一致)

`ida-headless-mcp/src/main.rs:484` 仍是 `ToolPolicy::unrestricted()`。BN 那边选择了约束它(flag 是 `global(true)`),理由是「一个用户打得出、却什么也不做的 flag 比不提供更糟」。IDA 侧接策略时留了「一并决定」,决定没做。

今天的实际后果:`bn tool patch.nop --read-only` 生效,`ida tool ... --read-only` 无效。

### 4. BN 两处欠测(**阻塞已解除**)

本文件此前多处记着「BN 侧没有授权」——**已不成立**。license 装在 `~/.binaryninja/license.dat`(0600),`bn-headless-mcp doctor` 报 `license: found via File`,51 工具,`tests/two_paths.rs` 10 条能跑。

于是这两条现在可以真跑,此前只有代码路径可读:

- `disasm.range` 的 `truncated`(需要真开一个 view)
- 负 offset 走 `page()`

> 跑 `two_paths` 时实测到一条**与本仓无关**的 BN 侧缺陷:`the_supervisor_forwards_worker_bytes_verbatim` 会红,但不是它声称的「supervisor 重新渲染」——它拿 supervisor 里开着的 view 和**另起一个进程重新分析**的 CLI 结果逐字节比,`function.callees` 对 `main` 一边 17 条一边 18 条(两边都报 `complete: true`)。`tests/two_paths.rs:115` 的注释里已经记着这个数字并加了串行化,但**串行跑照样复现**,所以那个缓解措施没打中根因。这是 BN 仓的账。

---

## 明确不建(不是停靠,是不做)

| 项 | 行数 | 为什么 |
|---|---:|---|
| 统一 supervisor / worker 进程模型 | — | 对进程模型的判断成立且有实测(池 + 租约 + 主线程循环 vs 一 view 一进程)。`SessionRouter` 已是这层向上的全部契约 |
| legacy SSE 进 kit | 464 | ida-pro-mcp 兼容客户端专用,BN 没有这段历史 |
| Resources(`ida://` URI)进 kit | 841 | 只有一个实例,且 URI scheme 与资源种类高度领域化。等 BN 真要 `bn://` 再按三次法则谈 |
| crash guard 进 kit | 88 + C | idalib 会 segfault,BN core 不走这条路 |
| `int_spec` / 地址规范化进 kit | 447 | `parse_int` 已在 kit(BN 已在用),再往上是领域 |
| 工具文档生成(`gen_tools_doc`) | 159 | BN 的 `docs/TOOLS.md` 是**设计文档**不是生成的清单,只有一个消费方 |
| CLI 瘦 client 模式(连 HTTP 端点) | — | 本进程直接执行已够用。两条码路都要写都要测,等真实需求 |
| `RESERVED` 静态清单加回来 | — | 它挡不住引擎自有命令(rjadx 的 `decompile`) |

---

## 停靠(不是取消)

| 项 | 解冻条件 |
|---|---|
| `real_clients.rs` 的 3 条 `#[ignore]` | 挂上定期触发(真实 `~/.claude.json` 等,不得污染、不得留 `.bak`)。不是合入门禁 |
| 探测超时只 kill 直接子进程 | ProcessGroup / JobObject 在 Unix 与 Windows 都落地 |
| Windows 未验证 | 路径(避开 etcetera 的 `config_dir()`)、Job Object、`claude` 委派默认关闭在 Windows 上实测 |
| BN / rjadx 的 skill **内容** | 通道已铺好(`Engine.skills_args` 填上即可),是否各配一份内容是单独决定 |

---

## 代价(必须明写)

- **kit 在请求路径上**。仍是库不是进程,不多一跳、不多序列化,但**爆炸半径大**:kit 的一个 bug 能让两个引擎的 MCP 面一起坏。
  > **这笔代价兑现过一次**:`output::Capped` 当时是手写的 `impl ServerHandler`,只实现了 28 个方法里的 6 个,剩下 22 个落回 rmcp 默认实现——IDA 的整个 resources 面(841 行,还在那里,只是够不着)下线了一个版本,三条传输面全中。跨引擎门禁没抓到,因为门禁问的是 tools。`decorate` 是结构性的对冲(默认就是转发,没有东西可忘),**toy-engine 的第二个能力(`toy://manifest`)是可检验的那一半——一个只发 tools 的参照引擎证明不了转发**。
- **两个引擎的发布节奏被绑在一起**。path 依赖之下,改 kit 要三个仓库同时验证。唯一的对冲是跨引擎契约扫描——它必须在合入前跑,不是因为它优雅。
- **MSRV 已被传递性作废**,见「当前待办 1」。

---

## 门禁

```bash
cargo test --workspace --all-features   # ← --all-features 不是可选的,见下
cargo test -p vibrev --test real_clients -- --ignored --nocapture   # 定期,不是每次
```

**`--all-features` 是必须的**:kit 的 `http` feature 默认关闭,不带它 `transport` 的测试一条都不编译,而 `cargo test -p vibrev-kit` 会照样打印一行绿。`toy-engine` 也必须在工作区里跑——契约扫描在那里跑的是真实的宏派生 catalog,不是手搭的 fixture。

**跨引擎门禁**:每个 kit 模块合入前,两个引擎都必须跑通各自的契约扫描(IDA 13 条、BN 3 条),否则 kit 改动不许合入。命令写在各引擎自己的 TODO 里——它们依赖各自的 checkout 位置,写在这里只会烂掉。

> 各引擎那条命令的 `--test` / `--bin` 选择器不能省:不带它们,过滤串会匹配到别的测试目标而不是契约扫描。

这条门禁是「kit 在请求路径上」这笔代价的唯一对冲:kit 被编进引擎,改它弄坏另一个引擎,在合入前没有别的东西能发现。

**两条都不需要反汇编器 license**:两个目录都从 `#[vibrev_tool]` 属性和 `session_tools()` 构建,全程不碰引擎 core。需要 license 的是行为测试(BN 真开一个 view 的那套)。

**IDA 这条不需要任何 `RUSTFLAGS`**:该仓 default 已是 `ida-94`,而 9.4 的 `idalib-sys` 把头文件里的包装全部加了 `inline`,重复符号归零。9.2 / 9.3 仍需 `-Wl,--allow-multiple-definition`,但它们是 `sdk/ida-92` / `sdk/ida-93` 两份替代 manifest,不在这条门禁的路径上。`idalib-sys` 声明 `links = "idalib"`,Cargo 不允许两份同时在图里——**一次构建只能对应一个 SDK**,三份 manifest 是结构性的。

**要实测 IDA 行为用 `sdk/ida-94`**。本机 IDA 可用(9.4 构建实测 `open_idb /bin/cat` 成功、161 个函数、`analysis_coverage.complete=true`)。用 SDK 9.2 编的二进制跑在 9.4 运行时上会崩,那是版本不匹配,不是 idalib 坏了。

用户真实配置(`~/.claude.json` / `~/.codex/config.toml` / `~/.config/Code/User/mcp.json`)测试不得污染、不得留 `.bak`。
