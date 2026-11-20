# Contributing to traefik-superheader

Thank you for your interest in contributing!

## Before you start

- Open an issue first for non-trivial changes so the approach can be agreed on
  before you invest time writing code.
- For typo fixes, doc improvements, and small bug fixes a PR without an issue
  is fine.

## Development setup

```bash
# Install devbox (https://www.jetify.com/devbox/)
devbox shell          # activates Go, TinyGo, dprint, etc.
make build            # build the Wasm plugin with TinyGo
make test             # run unit tests and the Traefik integration tests (needs Docker)
make lint             # golangci-lint
make format           # dprint + gofmt
```

See the [README](README.md) for how to use the plugin with Traefik.

## Pull request checklist

- [ ] `make test` passes
- [ ] `make lint` is clean
- [ ] `make format` produces no diff
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
      (`feat:`, `fix:`, `docs:`, `chore:` etc.) — semantic-release uses these to
      determine the next version

## Code style

- Standard `gofmt`/`goimports` formatting (enforced by CI)
- All exported symbols must have a doc comment

## License

By contributing, you agree your contributions will be licensed under the
[Apache-2.0 License](LICENSE).
