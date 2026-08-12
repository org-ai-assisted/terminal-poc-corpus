# Expected behaviour: crafted-hostile-log

## Class

crafted-hostile-log -- CyberArk 2021 "Don't trust this title" (composite)

## What the payload does

An ordinary-looking log that carries, mid-stream, three escapes that are never reset:
an OSC 0 window/tab-title set (to safe-demonstration wording), a stuck SGR colour, and
a DEC line-drawing charset shift. A traditional terminal is left with a hijacked title
and corrupted colour/charset after merely displaying the stream.

The content is deliberately non-scary (an `example.com` title, a NOTICE box) -- it
demonstrates the mechanism, not a threat.

## Verification (crafted-composite)

secure-terminal in CLI mode strips the OSC title-set and the charset shift, so
render_output contains neither the OSC escape (`ESC ] 0 ;`) nor the charset-shift escape
(`ESC ( 0`): the title is untouched and the line-drawing shows as literal ASCII. The
harness detects a hit if EITHER escape survives.

The stuck SGR colour is handled separately by secure-terminal's normal safe-colour
(contrast-guarding) behaviour, which keeps it readable rather than stripping it; that is
a rendering property, not part of this escape-survival check.

## Reference

https://www.cyberark.com/resources/threat-research-blog/dont-trust-this-title-abusing-terminal-emulators-with-ansi-escape-characters
