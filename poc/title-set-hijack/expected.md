# Expected behaviour: title-set-hijack

## Class

title-set-hijack -- documented class

## What the payload does

A benign log stream that carries, mid-stream, an OSC 0 escape
(`\033]0;example.com -- safe demonstration\007`). A traditional terminal honours it
silently and the window/tab title changes to text the program chose -- a spoof, since the
title is trusted UI chrome outside the scrollback.

## Verification (display-deception)

secure-terminal strips the OSC title-set, so the window title is unchanged and a banner
flags the blocked escape. The harness detects a hit via the display-deception mode.

## Reference

https://www.cyberark.com/resources/threat-research-blog/dont-trust-this-title-abusing-terminal-emulators-with-ansi-escape-characters
