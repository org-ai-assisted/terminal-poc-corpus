# Expected behaviour: alt-screen-hijack

## Class

alt-screen-hijack -- documented class

## What the payload does

A switch to the alternate screen buffer (ESC [ ?1049h) with no matching restore leaves a
traditional terminal stuck in a blank full-screen: the prompt is gone and the cursor is
hidden until `reset`. The canary token is written inside the alternate buffer, so on a
vulnerable terminal it only appears in the hijacked screen.

## Verification (screen-hijack)

secure-terminal strips the alternate-screen enable escapes (?1049h / ?1047h / ?47h) in CLI
mode, so render_output shows the canary as inert text and no alt-screen escape survives;
the harness detects a hit via the screen-hijack mode.

## Reference

https://secure-terminal.github.io
