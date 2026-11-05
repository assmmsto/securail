# Verifying a release

Releases are published on this fork's GitHub Releases page (upstream publishes its own,
starting with v0.1.0). Each can be checked in two independent ways: a published checksum that
detects a damaged download, and a build you reproduce yourself. Use both.

## 1. The published checksum

Each release carries `securail.py` and a `SHA256SUMS` manifest beside it:

    sha256sum -c SHA256SUMS          # macOS: shasum -a 256 -c SHA256SUMS

That detects a damaged or altered download. It cannot tell you that the publisher is
honest, because the publisher wrote the manifest too — which is exactly what rebuilding
answers.

## Why there is no GPG signature here

Upstream signs its releases with ArchiveGenocide's Ed25519 release key (fingerprint
`C24E C92B 12D6 670A 2516 065F 9B4D 5754 99AF A53C`, described in the upstream
repository's `docs/VERIFYING.md`). This fork holds neither that key nor one of its own, so
its releases carry no signature and ask nobody to trust a key. Rebuild and compare instead.

## 2. Rebuilding the single file yourself

This check does not depend on us at all. The single-file scanner is generated from the
repository source, so you can regenerate it from the release's tag and compare:

    git checkout v2.0.7
    python build/bundle.py
    sha256sum dist/securail.py

If the hash matches the one published with the release, that file holds this source and
nothing else. The build is deterministic, so a mismatch means something is wrong, not
merely different.

`verify-release` (`.github/workflows/verify-release.yml`) does the same thing on a clean
GitHub machine every time a release is published: it rebuilds from the tag, compares the
result with both the downloadable file and the manifest, and fails loudly if any of the
three disagree.

Running from source is the other half of the same idea: nothing is compiled, and every line
the tool executes can be read in the clone.

## Why there is no code signature

There is no signed Windows release and no signed installer. Code-signing certificates
require a verifiable legal identity and, in every route including
[SignPath Foundation](https://signpath.org/), named and publicly identified maintainers.
This project does not have them. It claims no certificate, signing service or signed binary,
and asks nobody to trust it because of one. Rebuild it and compare instead.

The fork publishes no prebuilt Windows, macOS or Linux programs; the release carries the
single-file Python build, which needs Python 3.8 or newer on the machine that runs it.
`programs.yml` and the signed program checksums in this file's earlier versions described
files this fork does not publish, so they are gone rather than promised.

## What a checksum does and does not tell you

A checksum proves these exact bytes are the ones the manifest lists. It does not prove the
program is free of bugs, and it does not authenticate the publisher. A rebuild proves the
file holds this source and nothing else. Neither proves the source is correct; reading it
does.

## Indicator updates are a separate trust path

`--update` downloads published indicator lists over HTTPS from a fixed list of official
sources, checks that each file parses before it replaces the previous copy, and records a
SHA-256 for every file; a cached file changed afterwards is refused at scan time. This
project does not sign those lists. They are only as trustworthy as their publishers'
repositories, and the release checksum does not cover them.

`daily-sources` (`.github/workflows/daily-sources.yml`) downloads all of them once a day and
records each source's indicator count, so a list that shrinks sharply, disappears, stops
downloading or goes stale shows up as a public build failure and an open issue — before a
scan silently relies on it.
