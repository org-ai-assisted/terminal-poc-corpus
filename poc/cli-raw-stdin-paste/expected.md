# Expected behaviour: cli-raw-stdin-paste

## Class

bracketed-paste-bypass (pastejacking; publicly documented class, no dedicated CVE).

## What the payload does

The standalone secure-terminal CLI runs the child under TERM=dumb, so bracketed
paste is off and a pasted stdin burst ending in a submit byte would auto-run the
command. This corpus pastes only the BENIGN canary marker-write.

## Verification (cli-paste-autoexec)

Real-effect oracle for the cli.py path: the payload is run through the real
_strip_burst_submit choke point (the CLI's stdin write path). A hit = the forwarded
burst still ends in a submit byte, so the command auto-runs.

secure-terminal treats a multi-byte burst ending in a submit as a paste and drops
the trailing submit, so the command waits at the prompt for the user's own Enter.

## Reference

https://secure-terminal.github.io
