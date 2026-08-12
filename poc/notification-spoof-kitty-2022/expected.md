# Expected behaviour: notification-spoof-kitty-2022

## Class

notification-spoof (kitty default OSC 9 / OSC 99 desktop notifications)

## What the payload does

A desktop-notification OSC (OSC 9 / 99) carries attacker-chosen text that pops up as a trusted-looking system notification. This is kitty's documented default behaviour, not a bug: any program's output can raise a real desktop notification. Here the notification text is the benign canary token.

## Verification (notification-spoof)

secure-terminal neutralizes this class; the harness detects a hit via the notification-spoof mode.

## Reference

Default behaviour: https://sw.kovidgoyal.net/kitty/desktop-notifications/

Distinct, patched bug (not reproduced here): CVE-2022-41322 was an escaping/validation flaw in kitty's notification handling, fixed in kitty 0.26.2, that allowed code execution only when the user clicked a crafted notification. This PoC demonstrates the default text spoof, not that RCE.
