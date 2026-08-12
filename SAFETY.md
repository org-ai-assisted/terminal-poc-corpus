# SAFETY

This repository is a **defensive test corpus**: a machine-readable collection of
publicly-disclosed terminal-emulator attack payloads, used to check whether a
terminal is vulnerable to a known class. It is built so that **reading the repo is
safe** and **running a payload is contained**. Read this file before anything else.

## 1. Payloads are stored ENCODED at rest (read-safe)

A terminal attack IS a stream of bytes that, when a terminal renders it, does
something. If we stored those bytes raw, then `cat`, `grep`, `git diff`, or a
GitHub file view would *feed the attack to your terminal* -- the repository itself
would be the weapon.

So every payload is stored **hex-encoded** in a `payload.hex` file (whitespace and
`#` comments ignored). Nothing in this repo, when displayed, emits an escape
sequence or control byte. The only place a payload is ever decoded to live bytes is
the sandbox harness, at run time, inside a disposable VM.

**Never** decode a payload and pipe it to a real terminal. Never `printf` or `echo`
the decoded bytes outside the harness.

## 2. Injection payloads are CANARY-FORKED (payload-safe)

A raw proof-of-concept that reaches code execution often does something destructive
to prove it (`rm`, open a calculator, exfiltrate a file). For every payload whose
class INJECTS content the terminal could run (the reflection / answerback /
title-report / OSC-command classes), we do not keep that action: the injected
content is rewritten so that **if the terminal executes it, it performs one safe,
unique, detectable action** -- it writes a marker token to a file the harness named
-- instead of anything harmful. A payload adapted this way is marked
`modified: true` in its `meta.yaml`, with `original_ref` pointing at the unmodified
upstream description (provenance only, never executed).

Not every class injects a command. The **denial-of-service** and **decoder-crash**
classes are resource/parser triggers, not command injections -- there is no attacker
command to fork, so they are kept as the real (`modified: false`) trigger. They
execute no code, but they CAN crash, corrupt, or freeze a *vulnerable* terminal, and
`reset` may not recover it -- that outcome is exactly what the test measures. So for
these classes section 3 is not optional: run them in the disposable sandbox only,
never against a terminal you care about. `tools/reproduce.py` labels each payload's
risk tier (SAFE / reset-recoverable vs CAUTION / may crash) from its verification
mode, and its `--self-test` asserts a crash/DoS payload is never mislabelled SAFE.

Each entry is reviewed (see the project's `ai-review` gate) before it is added.

## 3. Payloads run in a SANDBOX VM ONLY (run-safe)

The harness (`harness/run.py`) refuses to run unless it detects it is inside the
project sandbox VM, or an explicit override is set. It decodes a payload, feeds it
to the terminal-under-test running a shell, and checks whether the **canary marker
file** was written. Keep and run payloads in the sandbox VM only.

## 4. The harness self-checks (the machinery cannot silently do nothing)

A secure terminal never lets output inject input, so it never fires the canary --
which is indistinguishable from a *broken harness* that fires nothing and would
therefore call every terminal "secure" (fail-open). To close that gap, the harness
must first run an **always-firing positive control** (EICAR-style): a target known
to fire the canary. If the positive control is not observed, the harness is broken
and the run **fails loud** -- no "not vulnerable" verdict is trusted. `secure-terminal
--test-canary` is one such positive control.

## 5. Scope: public disclosures only

Only publicly-disclosed issues (CVEs, published write-ups) are collected, each with
a source link, a web-archive link, and author attribution. No 0-days.

## In one line

Encoded at rest, injections canary-forked, crash/DoS sandbox-contained,
self-checking, public-only.
