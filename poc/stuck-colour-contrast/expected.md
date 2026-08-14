# Expected behaviour: stuck-colour-contrast

## Class

stuck-colour-contrast -- documented class

## What the payload does

A benign log line, then an SGR colour escape (`\033[31;41m`, red foreground on a red
background) that is never reset. The line that follows is then the same colour as its
background -- invisible on a traditional terminal, which also leaves the colour stuck for
every later line. Here the hidden line is a safe-demonstration warning.

## Verification (display-deception)

secure-terminal's contrast guard forces the text to a legible colour rather than honouring
the attacker's stuck red-on-red, so the hidden warning is readable and the colour does not
persist past the payload. The harness detects a hit via the display-deception mode.

## Reference

https://secure-terminal.github.io
