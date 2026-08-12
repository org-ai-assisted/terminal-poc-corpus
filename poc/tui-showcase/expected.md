# Expected behaviour: tui-showcase

## Class

tui-showcase -- a corpus composite: ONE safe, HONEST, self-labeling educational file that
carries every terminal text-attack class at once, shaped as a full-screen
"WHAT YOU SEE vs WHAT IS THERE" board. It does NOT impersonate a real product or record;
its own title and framing say "safe demo", and each row openly names the class it shows.

## What the payload does

Cat'd at a shell in a traditional terminal, the file paints a boxed table whose every row
names a class and shows a live example of it:

- Homoglyph (Cyrillic)  -- `example.com` whose `a` is U+0430;
- Homoglyph (Greek)     -- `google.com` whose `o` is U+03BF;
- ASCII look-alike      -- `rnicrosoft.com` (rn reads as m; NO Unicode);
- Bidi override (RTL)   -- stores `report cod.exe`, DISPLAYS `report exe.doc` (U+202E);
- Zero-width space      -- `veri<U+200B>fied`;
- Invisible / BOM       -- `<U+FEFF>balance`;
- Combining (Zalgo)     -- stacked U+030x marks on letters;
- Fullwidth forms       -- U+FF2x wide look-alikes;
- Control byte          -- prints `FAILED` then `CR` + `ESC[2K` and repaints `OK`;
- Hidden by colour (SGR)-- fg == bg, so the text is invisible;
- Charset shift (DEC)   -- `ESC(0` renders letters as line-drawing;
- Hyperlink (OSC 8)     -- visible `example.com`, target `https://example.org`;
- Notification (OSC 9)  -- a desktop notification with safe wording;
- Title hijack (OSC 0)  -- sets the window title (labeled; effect is the title bar);
- Alt-screen (?1049h)   -- switches to the alternate screen (labeled; effect is the screen);
- Honest foreign (Greek)-- real Greek text -- the NON-attack contrast case.

The board is DISPLAY-ONLY: every row is a class it can safely FIRE and show. Classes that
reach OUTSIDE the display are deliberately NOT in the board -- a desktop notification
(OSC 9), the clipboard (OSC 52), the shell input (DSR reflection / answerback) and the
reflected-command RCE. Each of those is fired and conformance-tested live in the SANDBOX
by its own PoC (`notification-spoof`, `osc52-clipboard-write`, `device-status-reflection`,
`title-report-echoback`), and all are compared -- with the crash/decoder classes -- on
secure-terminal.github.io. They are not shipped as a live cat-able file.

So the only state this file changes is the DISPLAY: the window title (OSC 0) and the
alternate screen (?1049h), both undone by `reset`. A plaintext warning is the file's FIRST
bytes, the board runs on the alternate screen (real scrollback preserved), and the footer
says to run `reset`. Nothing is copied, typed, executed or destroyed.

## Verification (composite-multiclass)

secure-terminal in CLI mode strips every escape and boxes every non-ASCII byte. The
detector runs secure-terminal's `render_output(payload, 'box')` and reports a HIT if ANY
embedded class survived, i.e. if the rendered text still contains:

- any ESC (`0x1b`) -- one check that covers EVERY live escape class, since each carries an
  ESC: the OSC-0 title-set, the DEC charset-shift (`ESC ( 0`), the alt-screen enable
  (`ESC [ ? 1049 h`), and the OSC 8 hyperlink; OR
- a NUL (`0x00`, a truncation byte); OR
- any non-ASCII code point (a surviving homoglyph, bidi control, zero-width, combining,
  fullwidth, or foreign character).

A neutralized render is pure ASCII with no ESC and no NUL: the title is untouched, the
terminal never leaves the primary screen, the hyperlink escape is gone, the line-drawing
shows as literal text, and every hidden/reordered/look-alike byte is an inert boxed
placeholder. Because a regression in ANY single live class re-introduces an ESC, a NUL, or
a non-ASCII byte, this one assertion covers all of them: it fails if even one is silently
passed through. (The reach-outside classes -- OSC 9 / OSC 52 / DSR -- are not in this
board at all; their live neutralization is asserted by their own sandbox PoCs, not this
one.)

Three rows are present for education but are NOT caught by this detector, and the board is
honest about why:

- the ASCII look-alike (`rn` for `m`) is pure ASCII -- there is nothing to strip, and a
  Unicode-aware tool cannot catch it; only reading character by character does;
- the OSC 8 link's visible-text-vs-target mismatch (does the visible text differ from the
  resolved target?) is conformance-checked by the dedicated `osc8-hyperlink-phishing` PoC,
  which uses a different observable; here only the escape's survival is asserted;
- the control-byte CR+erase row uses a lone `\r`, which secure-terminal's WIDGET
  deliberately HONORS as a line-local edit (a `\r` overwrites only the line being written,
  never an earlier one -- vertical addressing IS stripped). So after the escape colour is
  removed the `\r`+`OK` can still overwrite `FAILED` on that one line: the widget render
  does NOT neutralize this class, and this detector does not claim it does. The stricter
  `stcat` path is what strips `\r` and reveals both; the board's subtitle credits `stcat`,
  not the widget, for this row. This matches the documented secure-terminal limitation
  ("erase-in-line is honoured, so a program can overwrite the line it is writing").

## Reference

Composite of the single-class PoCs in this corpus (crafted-hostile-log,
trojan-source-bidi, homoglyph, alt-screen-hijack, notification-spoof,
osc8-hyperlink-phishing), assembled for the secure-terminal comparison at
https://secure-terminal.github.io/comparison/
