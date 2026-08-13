# Expected behaviour: osc52-clipboard-read

## Class

osc52-clipboard-read (clipboard exfiltration; publicly documented class, no
dedicated CVE).

## What the payload does

OSC 52 with a '?' payload (ESC ] 52 ; c ; ? BEL) asks the terminal to REPLY with
the system clipboard, base64-encoded, onto the program's stdin -- a silent
clipboard read that can leak passwords or keys.

## Verification (reflection)

Reflection oracle: the query is fed as program output with every OSC reach-out
feature enabled, and the bytes written back to the pty are spied. A hit = any
write-back.

secure-terminal never answers an ungranted query: even with osc_clipboard_read on,
an undecided tab only raises the ask-once dialog and writes nothing. The granted
direction (rate-limited, base64-only, size-capped) is covered by the dist-ai widget
test.

## Reference

https://secure-terminal.github.io
