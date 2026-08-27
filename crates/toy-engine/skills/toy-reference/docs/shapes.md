# Which parameter shapes survive the trip to a command line

The derived CLI maps a tool's JSON Schema onto clap. Most shapes have an
obvious spelling; one does not.

- **Scalars** — `string`, `integer`, `number`, `boolean` — become flags. A
  boolean becomes a pair (`--with-body` / `--no-with-body`) so that "not
  specified" stays distinct from "false".
- **Enums** become a `value_parser` over the variants, so an unknown value is a
  usage error rather than a request the engine has to reject.
- **Arrays of scalars** become repeatable flags.
- **Nested objects** have no spelling. A flag namespace (`--report.title`) would
  work for one level and fall apart at two, and it would collide with any tool
  whose parameter legitimately contains a dot.

The last one is why `report.build` appears in `tools/list` and not in
`toy tool --help`. This is a deliberate gap, not an oversight: a tool that the
CLI cannot express faithfully is better absent than half-mapped.
