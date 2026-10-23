# Contributing

Thank you for helping. receipts-log is a transparency log and witness for
verifiable-receipts, written in Go with the standard library only.

## Reporting

- **A security flaw**: report it privately, as `SECURITY.md` says. Don't
  open a public issue.
- **A bug**: open an issue with the version or commit, the requests or
  store file that show it, what you expected and what happened (test keys
  only).
- **A proposal**: open an issue first for anything that changes the API
  (`API.md`), the store format, or what the log admits.

## Changing code

1. Fork, branch from `main`, and open a pull request. CI must pass and
   every review conversation must be resolved before it merges; `main`
   takes merge commits only.
2. `internal/vaos` is a copy of the verifiable-receipts Go verifier. Change
   the verifier there first, then copy it here and update `VR_REF` in
   `.github/workflows/ci.yml`; the interop tests check that the copy and
   the fixtures in `testdata/conformance/` match that commit.
3. Add tests with the change, and a fuzz target for new parsing code.

## The checks CI runs

```bash
make check            # gofmt, go vet, staticcheck, go test -race
make fuzz FUZZTIME=10s
make interop VERIFIABLE_RECEIPTS_DIR=../verifiable-receipts   # needs node 22.6+, python with cryptography
make docker
```

## Style

- Plain, declarative prose in docs and comments; each fact once.
- Commit messages: a subject line under 72 characters, a blank line, then
  what changed and why.
- No dependencies beyond the Go standard library.

By contributing you agree that your contribution is licensed under the
Apache License 2.0 (`LICENSE`).
