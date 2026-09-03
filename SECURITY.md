# Security Policy

## Scope and threat model

`system-informer-mcp` is a local tool. It speaks MCP over stdio to an MCP client
running on the same machine and, through native Windows APIs, can inspect and
control the local system with the privileges of the account it runs under. It
does **not** open any network listener, and it never transmits data anywhere.

It exposes the same capabilities the System Informer GUI already grants to an
administrator. Destructive or irreversible actions are gated behind an explicit
`"confirm": true` argument, and terminating a Windows-critical process requires
an additional `allow_critical` flag.

Because the server can read/write process memory, close handles, and control
services when elevated, you should only connect it to an AI client and prompts
you trust, and prefer running it non-elevated unless you need full coverage.

## Reporting a vulnerability

If you find a security issue, please **do not open a public issue**. Instead,
use GitHub's private vulnerability reporting:

- Go to the **Security** tab of this repository → **Report a vulnerability**.

Please include reproduction steps and the impact. I'll acknowledge within a
reasonable time and coordinate a fix and disclosure.
