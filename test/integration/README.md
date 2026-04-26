# Integration tests

Container-based integration tests. Spins up real Kerberos KDCs in Docker; tests run against them.

The integration tests live in their own Go sub-module so the testcontainers-go dependency does not pollute the main module's dependency graph.

## Requirements

- Docker daemon reachable from the test host.
- Go matching the version declared in `go.mod`.

## Running

```sh
cd test/integration
INTEGRATION=1 go test ./...
```

Without `INTEGRATION=1` tests skip via `test.Integration(t)`. Without Docker available they skip via `framework.SkipIfNoDocker(t)`.

## Backends

| Backend | Entry point | Cold start |
|---|---|---|
| MIT krb5 | `framework.StartMITKDC(ctx)` | ~5s |

## Adding tests

Place new test files under `suites/`. Stand up the fixture once per test binary in `TestMain` and share it across tests:

```go
package suites

import (
    "context"
    "log"
    "os"
    "testing"

    "github.com/f0oster/gokrb5/test"
    "github.com/f0oster/gokrb5/test/integration/framework"
)

var mitKDC framework.KDC

func TestMain(m *testing.M) {
    if os.Getenv(test.IntegrationEnvVar) != "1" {
        os.Exit(m.Run())
    }
    kdc, cleanup, err := framework.StartMITKDC(context.Background())
    if err != nil {
        log.Printf("MIT KDC setup failed: %v; tests will skip", err)
        os.Exit(m.Run())
    }
    mitKDC = kdc
    code := m.Run()
    cleanup()
    os.Exit(code)
}
```

The KDCs are read-only across tests (each test acquires fresh tickets; nothing mutates the principal database), so a single shared fixture is fine for typical tests.

## Adding a backend

Each KDC backend has two parts:

1. `fixtures/<name>/` — Dockerfile that installs the KDC binaries. The image is generic; the framework provisions realms and principals at runtime via exec.
2. `framework/<name>.go` — implements the `KDC` interface, declares the topology to provision, and wraps testcontainers-go to manage the containers' lifecycle.

`mit-kdc/` and `mit.go` are the reference implementations.
