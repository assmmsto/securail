# Code signing policy

This fork publishes no compiled programs, so there is nothing to code-sign. The release
carries the single-file Python build, `securail.py`, which needs no signature because
nothing in it is compiled: every line it runs can be read in the clone, and
`verify-release` (`.github/workflows/verify-release.yml`) rebuilds it from the tag and
compares the result with the published file and its `SHA256SUMS`.

Upstream applies to [SignPath Foundation](https://signpath.org) for a certificate covering
its own Windows program. That certificate would cover files built by upstream, not by this
fork, so this repository claims no certificate, signing service or signed binary and
reproduces no part of that policy here.

## Privacy

This program does not send information about your computer or phone anywhere. It connects to
the internet only when you ask it to: updating the indicator and exploited-software lists,
checking for a newer version, and downloading the Android collector, each from the fixed
official sources listed in the [README](../README.md). Reports are saved only where you choose.
