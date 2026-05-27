# Licensing

This document records the license for each component of the Relix
repository and the reasoning behind the structure.

## Component license table

| Component                                | License           | Effect                                                                                              |
| ---------------------------------------- | ----------------- | --------------------------------------------------------------------------------------------------- |
| `crates/relix-core/`                     | Apache-2.0        | May be embedded in any project, including commercial; includes a patent grant.                      |
| `crates/relix-rules/`                    | Apache-2.0        | Same as above.                                                                                      |
| `crates/relix-cli/` (the gateway binary) | AGPL-3.0-or-later | Use is unrestricted. Modifications run as a network service must be made available under AGPL-3.0.  |
| `rules/` (threat-intel YAML)             | CC-BY-SA-4.0      | Free to use; redistributed modifications must be licensed under CC-BY-SA-4.0; attribution required. |
| `examples/`                              | MIT               | Copying into other projects is unrestricted, with attribution.                                      |
| `docs/`                                  | CC-BY-4.0         | Translation, quotation, and republication are permitted, including commercially, with attribution.  |

Summary: the engine is freely embeddable; the gateway binary cannot
be repackaged into a closed-source hosted service without
contributing modifications back; the threat-intelligence rule set
remains a community-licensed corpus.

## Rationale

### Engine and rules library: Apache-2.0

`relix-core` is a pure-Rust library with no I/O dependency. It is
intended to be embeddable in third-party gateways (such as
claude-code-router, LiteLLM, OpenRouter, Portkey, or custom
enterprise proxies). Apache-2.0 is the prevailing license in the
Rust ecosystem and includes an explicit patent grant; MIT alone
would not provide the patent grant.

### Gateway binary: AGPL-3.0-or-later

The gateway binary is the component most exposed to being forked
into a hosted product without contribution back. AGPL-3.0 closes
the network-service exception that GPL-3.0 leaves open: a modified
copy of Relix offered as a network service must be made available
in source form under the same license.

AGPL applies to modifications of the Relix source itself. It does
not apply to:

- Programs that send traffic through an unmodified Relix instance.
- Programs that link against `relix-core` (which is Apache-2.0).
- Programs that read the source for reference.

### Rules: CC-BY-SA-4.0

The detection rules are documentation of attack patterns. CC-BY-SA-4.0
is the license used by Wikipedia and the MITRE ATT&CK framework:
public, attributable, share-alike. The license prevents the corpus
from being privatized into a paid feed.

### Examples and documentation

Examples are MIT to remove any doubt about copying into other
projects. Documentation is CC-BY-4.0 to permit translation and
republication.

## Common scenarios

### Running Relix to protect a local agent

No license obligations apply.

### Embedding `relix-core` in a third-party gateway

Apache-2.0. Include `LICENSE-APACHE` and preserve the copyright
notice.

### Operating a hosted service based on a modified Relix

AGPL-3.0 requires that recipients of the service be able to obtain
the source code of the modifications. The recommended path is
upstream contribution.

### Bundling Relix into a commercial product

Running an unmodified Relix as a separate process alongside a
commercial product does not impose AGPL obligations on the
commercial product. Bundling a modified Relix into a commercial
product requires either AGPL compliance for the bundled work or a
separate commercial license.

### Maintaining private rules

Internal modification of `rules/` is unrestricted. Public
distribution requires CC-BY-SA-4.0.

## Contributor License Agreement

Code contributions require a signed Contributor License Agreement.
The CLA permits the project to relicense contributions under future
OSI-approved open-source licenses and to grant additional commercial
licenses alongside the open-source license.

The CLA exists to keep license decisions correctable as the project
evolves. Without a CLA, future license adjustments would require
unanimous consent from every prior contributor.

CLA signing is automated via the
[cla-assistant](https://cla-assistant.io) bot on first pull request.
The full CLA text is in [`CLA.md`](CLA.md).

## Why not BSL or SSPL

The Business Source License and Server Side Public License are not
OSI-approved open-source licenses. Adopting one would prevent
inclusion in Linux distribution package repositories and would
foreclose certain forms of community participation. AGPL-3.0 with a
CLA achieves the same protection against unauthorized hosted forks
while remaining OSI-approved.

## Why not MIT or Apache for the entire project

A fully permissive license would allow a third party to repackage
the gateway as a closed hosted service without contributing
improvements back. AGPL-3.0 on the gateway binary prevents this
while preserving the embeddability of the engine through Apache-2.0.

## Inquiries

Licensing questions should be filed as issues with the `licensing`
label on the main repository. A dedicated mailbox will be provisioned
alongside the public website.
