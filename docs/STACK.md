# Stack

## Used

| Tool | Why |
|---|---|
| Go >= 1.23 | Oldest supported release line; one toolchain covers build, test and format. |
| Go modules | Built-in dependency management with checksum verification (`go.sum`). |
| gofmt + go vet | The canonical formatter and static checks; no configuration to maintain. |
| go test | Built-in tests, runnable examples, race detection and coverage. |
| `net.DefaultResolver` | Standard-library resolver used by the CLI; tests inject a fake `Resolver`. |

## Discarded

| Tool | Why not |
|---|---|
| External dependencies | None are allowed or used; the implementation is standard library only. |
| Online checkers | Manual and not scriptable in CI; the library returns stable rule codes and accepts a fake resolver. |
