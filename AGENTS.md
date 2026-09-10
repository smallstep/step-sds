# AGENTS.md

Guidance for AI coding agents working in this repository.

## Overview

`step-sds` is a server-side implementation of the Envoy Secret Discovery Service (SDS). Envoy connects to it over gRPC (mTLS over TCP, or a Unix domain socket) and asks for TLS secrets by resource name; step-sds turns each name into a certificate request against a `step-ca` instance, streams the resulting certificate chain and key back to Envoy, and pushes renewals automatically. Module path: `github.com/smallstep/step-sds`. Single binary at `cmd/step-sds`. Public, Apache-2.0.

Main dependencies: `github.com/smallstep/certificates` (CA client, provisioner, `pki` helpers), `go.step.sm/crypto` and `go.step.sm/cli-utils` (PEM/key handling, CLI scaffolding), and `github.com/envoyproxy/go-control-plane/envoy` (SDS/xDS v3 protobuf types).

## Commands

```bash
make bootstrap          # install golangci-lint, govulncheck, gotestsum into $(go env GOPATH)/bin
make build              # CGO_ENABLED=0 build to bin/step-sds (this is what CI runs, as V=1 make build)
make test               # gotestsum with coverage (this is what CI runs)
make lint               # golangci-lint (config curl'd from smallstep/workflows) + govulncheck
make fmt                # goimports -l -w on all .go files (goimports is not installed by bootstrap)
```

Without `gotestsum`, plain `go test ./...` runs the same suite:

```bash
go test ./...
go test -run TestService_StreamSecrets ./sds/
```

Build and unit tests run offline in well under a minute and need no env vars, Docker, or private modules. `make generate` exists but there are no `go:generate` directives, so it is a no-op. `make integration` references a `./integration/` directory that does not exist, and the README's `make docker` is not a Makefile target either; do not use them.

Run locally:

```bash
bin/step-sds init --ca-url https://ca.example.com:9000 --root ~/.step/certs/root_ca.crt   # writes $STEPPATH/sds/* and $STEPPATH/config/sds.json
bin/step-sds init --ca-url ... --root ... --uds                                            # Unix-socket variant, no server certs
bin/step-sds run $STEPPATH/config/sds.json [--password-file f] [--provisioner-password-file f]
```

`init` needs a reachable `step-ca`: it lists the CA's JWK provisioners, prompts you to pick one, and writes its issuer and key ID into `sds.json`. `run` needs the CA reachable at start and on every renewal.

## Architecture

```
step-sds/
├── cmd/step-sds/main.go   # urfave/cli app; sets Version/BuildTime via ldflags; STEPDEBUG and STEP_PROF_ADDR handling
├── commands/
│   ├── init.go            # `step-sds init`: builds a root/intermediate/server/client PKI with minica, picks a JWK provisioner from the CA, writes sds.json
│   └── run.go             # `step-sds run`: loads config, builds the gRPC server (mTLS creds if network is tcp*), registers sds.Service
├── sds/
│   ├── config.go          # Config / ProvisionerConfig structs (JSON), Validate(), LoadConfiguration()
│   ├── service.go         # sds.Service: StreamSecrets / FetchSecrets, peer-cert authorization, ACK/NACK + nonce/version bookkeeping
│   ├── renewer.go         # secretRenewer: bootstraps a ca.Client from a token, signs one cert per resource name, renews at validity/3
│   ├── utils.go           # builds envoy.extensions.transport_sockets.tls.v3.Secret payloads (TlsCertificate / ValidationContext)
│   └── testdata/          # sds.json, bad.json, fail.json, root_ca.crt used by config tests
├── logging/               # logrus wrapper + gRPC unary/stream interceptors; config comes from the "logger" block of sds.json
├── examples/docker/       # docker-compose demo: step-ca + step-sds (TCP and UDS) + Envoy + two backends
├── examples/emojivoto/    # Kubernetes demo (Makefile applies ca.yaml then emojivoto.yaml)
├── docker/Dockerfile.step-sds   # release image (FROM smallstep/step-cli)
├── debian/, .goreleaser.yml     # packaging; release.yml builds archives, deb/rpm, and the Docker image on v* tags
└── Makefile
```

### Request flow

1. Envoy sends a `DiscoveryRequest` with `ResourceNames`. `validateRequest` checks the peer TLS certificate against `authorizedIdentity` (common name) and `authorizedFingerprint` when the listener is TCP; UDS connections skip the check.
2. For each resource name the service mints a CA token via `ca.Provisioner.Token(name)`. The names `trusted_ca` and `validation_context` are special: they return the CA's root bundle as a `ValidationContext` secret instead of a leaf certificate.
3. `newSecretRenewer` bootstraps a `ca.Client` from the first token, signs a certificate per name (the name is the token subject, so it becomes the certificate CN and SAN), and schedules renewal at one third of the certificate validity (or every 8 hours for validation-context-only streams).
4. `StreamSecrets` sends a `DiscoveryResponse`, then loops: new requests from Envoy are matched by nonce/version (ACK/NACK logged), and renewals from the renewer channel push a fresh response unsolicited. `FetchSecrets` is the one-shot variant. `DeltaSecrets` is not implemented.

## Conventions

- **CLI**: `urfave/cli` v1 with `go.step.sm/cli-utils` (`command.Register` in each `commands/*.go` `init()`, `errs.*` for flag/argument errors, `ui.Prompt*` for interactive input). Help text is Markdown rendered by `cli-utils/usage`.
- **Errors**: `github.com/pkg/errors` (`errors.Wrap`, `errors.Errorf`). gRPC-facing errors in `sds/service.go` use `status.Errorf(codes.X, ...)`. `STEPDEBUG=1` prints `%+v` stack traces.
- **Logging**: logrus via the local `logging` package. Formatter (`text` or `json`), `traceHeader`, and `timeFormat` are read from the `logger` object in `sds.json`.
- **Config**: a single JSON file passed to `run`; no env-var or flag overrides beyond the two password-file flags. `Config.Validate` requires `crt`/`key` when `network` is `tcp*` and always requires `provisioner.{issuer,kid,ca-url,root}`.
- **Testing**: table-driven tests with `github.com/smallstep/assert` (older) and `testify` (`assert`/`require`, newer). `sds/utils_test.go` has the shared helpers: `caServer()` is an `httptest` fake of the step-ca HTTP API (`/provisioners`, `/sign`, `/renew`, `/roots`, ...), `caProvisioner()` wraps it, and `tlsCerts()`/`rootCAs()` build in-memory certs. gRPC service tests use `google.golang.org/grpc/test/bufconn`. There are no mocks or golden files.
- **Versioning**: `main.Version` and `main.BuildTime` come from ldflags (Makefile derives the version from `git describe`; goreleaser sets it from the tag). Do not hardcode versions.

## Environment variables

| Variable | Effect |
|----------|--------|
| `STEPPATH` | Base directory `init` writes into (`$STEPPATH/sds/`, `$STEPPATH/config/sds.json`), via `cli-utils/step`. `run` takes the config path explicitly. |
| `STEPDEBUG=1` | Full error stack traces and panic details on stderr |
| `STEP_PROF_ADDR` | If set, starts a `net/http/pprof` listener at that address |

## CI

`.github/workflows/ci.yml` calls the shared `smallstep/workflows` `goCI` workflow: build (`V=1 make build`), test (`gotestsum` on `stable` and `oldstable` Go), golangci-lint, govulncheck, and CodeQL. `actionci.yml` runs actionlint and zizmor over the workflow files (`.github/zizmor.yml` holds the exemptions). Tags matching `v*` trigger `release.yml`, which reruns CI and then runs goreleaser and the Docker image build.
