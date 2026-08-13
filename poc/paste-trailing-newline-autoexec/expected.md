# Expected behaviour: paste-trailing-newline-autoexec

## Class

bracketed-paste-bypass (pastejacking; publicly documented class, no dedicated CVE).

## What the payload does

A pasted string ending in a newline carries its own submit. A terminal that
delivers paste as typed input runs the pasted command the instant it is pasted,
before it can be read. This corpus pastes only the BENIGN canary marker-write, so a
hit merely writes a harmless token file.

## Verification (paste-autoexec)

Real-effect oracle: the payload is fed through the REAL GUI paste path
(insertFromMimeData) into a line-mode terminal and the bytes written to the child
are spied. A hit = a submit byte (CR) reaches the child with NO review interposed.

secure-terminal strips a single-line paste's trailing submit, so the command waits
at the prompt for the user's own Enter and no CR is written.

## Reference

https://secure-terminal.github.io
