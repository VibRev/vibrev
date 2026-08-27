---
name: toy-reference
description: How toy-engine's five tools map onto its CLI, and which shapes the CLI cannot express
---

# toy-engine reference

`toy-engine` exists to prove one thing: a tool defined once drives both the MCP
surface and the CLI. This skill is the second half of that proof — a skill is
knowledge a tool signature cannot carry, and "which of these tools has no CLI
form" is exactly that kind of knowledge.

## The five tools

| Tool | MCP | CLI | Why it is here |
|---|---|---|---|
| `ping` | ✅ | `toy tool ping` | No parameters at all |
| `decompile` | ✅ | `toy tool decompile <func>` | Positional, optional flag, boolean pair, enum |
| `binary.functions` | ✅ | `toy tool binary functions` | `group.verb` nesting, array parameter |
| `annotation.rename` | ✅ | `toy tool annotation rename` | Integer accepting `0x`, and a mutation |
| `report.build` | ✅ | — | A nested object, which the CLI cannot map |

## The one that has no CLI form

`report.build` takes a nested object. A command line is a flat list of strings,
so there is no honest flag spelling for it. The derived CLI therefore does not
offer it, rather than offering something that only works for the shallow cases.

See [docs/shapes.md](docs/shapes.md) for what that rule covers and what it does
not.
