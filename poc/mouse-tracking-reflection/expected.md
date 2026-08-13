# Expected behaviour: mouse-tracking-reflection

## Class

mouse-tracking-reflection (xterm mouse reporting; publicly documented class, no
dedicated CVE).

## What the payload does

Program output enables xterm mouse tracking (DECSET ?1003h any-event + ?1006h SGR
extended). A terminal that implements it then writes an ESC[<...M/m mouse report
onto the child's stdin for every mouse move / click / wheel -- output turning later
user pointer motion into injected input.

## Verification (mouse-tracking-reflection)

Real-effect oracle: enable tracking with the payload, then post REAL QMouseEvent
press/move/release and a QWheelEvent over the offscreen widget and spy _write. A
hit = any mouse-report write-back to the pty.

secure-terminal has no mouse-report path at all, so no mouse action ever writes to
the child.

## Reference

https://secure-terminal.github.io
