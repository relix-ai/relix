# Architecture decision records and design RFCs

This directory holds the design notes that govern the implementation
of Relix. Every non-trivial change to the gateway, the protocol
parsers, the rule schema, or the audit-log shape lands as an RFC
here before code lands in a milestone branch.

## Index

| ID   | Title                                                                 | Status | Target            |
| ---- | --------------------------------------------------------------------- | ------ | ----------------- |
| 0001 | [Multi-protocol gateway architecture](0001-multi-protocol-gateway.md) | Draft  | v0.2              |
| 0002 | [OpenAI protocol adapter](0002-openai-protocol-adapter.md)            | Draft  | v0.2 (step 3)     |
| 0003 | [Hardening plan](0003-hardening-plan.md)                              | Draft  | v0.2-step3 → v0.3 |

## Process

1. Open a pull request adding a new file `NNNN-title.md` based on
   the structure of an accepted RFC.
2. Discussion happens on the PR. Substantial revisions amend the
   PR; do not open follow-up RFCs unless the scope shifts.
3. An RFC is merged with status `Accepted` once a maintainer
   approves and no open objections remain.
4. Implementation lands in subsequent PRs that reference the RFC.
5. Once the implementation is shipped, the RFC is amended to
   `Implemented` and the targeted milestone is recorded.

Status values: `Draft`, `Accepted`, `Implemented`, `Superseded`,
`Rejected`. Superseded RFCs link forward to the replacement.

## Scope

RFCs are required for:

- changes to the rule schema, audit log format, or any field in
  `relix-core` that has been advertised as stable;
- new protocol parsers;
- new dependencies in `relix-core`;
- changes to the license or trust model of the rule corpus.

RFCs are not required for:

- bug fixes;
- internal refactors that preserve external behavior;
- new rules in `rules/` (those go through ordinary review).
