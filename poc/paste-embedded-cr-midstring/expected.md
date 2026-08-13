# Expected behaviour: paste-embedded-cr-midstring

## Class

bracketed-paste-bypass (pastejacking; publicly documented class, no dedicated CVE).

## What the payload does

A carriage return embedded mid-paste submits everything before it. A terminal that
delivers paste as typed input runs that hidden first command the instant the paste
lands. This corpus hides only the BENIGN canary marker-write before the CR.

## Verification (paste-autoexec)

Real-effect oracle: fed through the REAL GUI paste path (insertFromMimeData). A
paste carrying an embedded CR / newline MUST be held for review (a review is
requested and nothing is written). A hit = a CR reaches the child unreviewed.

secure-terminal holds this paste for review whatever the warn setting, so nothing
auto-runs.

## Reference

https://secure-terminal.github.io
