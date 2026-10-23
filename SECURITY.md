# Security

## Reporting a vulnerability

Report a suspected flaw privately, through a GitHub security advisory:
<https://github.com/christiaan839-beep/receipts-log/security/advisories/new>
(the repository's **Security** tab, then **Report a vulnerability**).
Don't open a public issue for it.

If you cannot use GitHub, email `sovereign.systems007@gmail.com` with
`[security]` at the start of the subject.

Please include the version or commit, what you expected and what happened,
and the requests, receipts, keys or store file that show it, using test
keys only, never a key in real use.

You should get a first reply within seven days. A fix is developed in the
private advisory, and the advisory is published with the release that
fixes it, crediting you unless you ask otherwise.

## Scope

In scope: anything that lets the log admit a receipt whose signature does
not verify under a configured issuer key; serve a tree head, inclusion
proof or consistency proof that does not match its entries; drop, reorder
or rewrite an acknowledged entry without a failed consistency check; make
the witness cosign a tree head that does not extend the last one it signed;
or crash, hang or exhaust memory on input a client can send.

Out of scope: an issuer key that is itself compromised, a log operator who
runs modified code (that is what witnesses are for), and vulnerabilities in
dependencies or base images that do not affect this code (report those
upstream).

## Supported versions

Fixes go into `main` and the latest release; older versions are not
patched. Releases are built and published from CI with signed provenance
(see `RELEASING.md`).
