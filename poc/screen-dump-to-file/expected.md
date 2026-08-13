# Expected behaviour: screen-dump-to-file

## Class

screen-dump-to-file -- documented class (DEC/xterm Media Copy / printer controller)

## What the payload does

The payload carries DEC/xterm Media Copy escapes: printer-controller-on (ESC [ 5 i),
print-screen (ESC [ i) and printer-controller-off (ESC [ 4 i). On a terminal that
implements printer / Media Copy support, ESC [ 5 i routes the host output stream directly
to the configured printer command or a file. This means the canary token (and the ESC [ i)
are streamed directly to the printer, silently exfiltrating them (a stream-to-printer, not a screen dump).

## Verification (screen-dump-to-file)

secure-terminal has no printer / Media Copy path and strips every escape, so render_output
leaves the canary as inert text and NO Media Copy sequence (CSI ... i) survives; the
harness detects a hit via the screen-dump-to-file mode (a surviving CSI ... i).

## Reference

https://secure-terminal.github.io
