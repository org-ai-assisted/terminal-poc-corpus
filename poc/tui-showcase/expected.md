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

The board also states, honestly, which classes it deliberately does NOT fire because they
reach into your session -- clipboard write (OSC 52) and input reflection / answerback --
and that crash/decoder classes are out of scope; and it tells the reader to run `reset`
(the title, alt-screen and notification are changed on purpose). There is no executable,
destructive, clipboard-altering or input-injecting content.

## Verification (composite-multiclass)

secure-terminal in CLI mode strips every escape and boxes every non-ASCII byte. The
detector runs secure-terminal's `render_output(payload, 'box')` and reports a HIT if ANY
embedded class survived, i.e. if the rendered text still contains:

- the OSC-0 title-set (`ESC ] 0 ;`) or the DEC charset-shift (`ESC ( 0`), OR
- an alternate-screen enable (`ESC [ ? 1049 h` / `?1047h` / `?47h`), OR
- an OSC 8 hyperlink (`ESC ] 8 ;`) or OSC 9 notification (`ESC ] 9 ;`) escape, OR
- any non-ASCII code point (a surviving homoglyph, bidi control, zero-width, combining,
  fullwidth, or foreign character).

A neutralized render is pure ASCII with none of those escapes: the title is untouched,
the terminal never leaves the primary screen, the hyperlink/notification escapes are gone,
the line-drawing shows as literal text, and every hidden/reordered/look-alike byte is an
inert boxed placeholder. Because a regression in ANY single class re-introduces a
surviving escape or non-ASCII byte, this one assertion covers all of them: it fails if
even one class is silently passed through.

Two rows are present for education but are NOT caught by this detector, and the board is
honest about why:

- the ASCII look-alike (`rn` for `m`) is pure ASCII -- there is nothing to strip, and a
  Unicode-aware tool cannot catch it; only reading character by character does;
- the OSC 8 link's visible-text-vs-target mismatch (does the visible text differ from the
  resolved target?) is conformance-checked by the dedicated `osc8-hyperlink-phishing` PoC,
  which uses a different observable; here only the escape's survival is asserted.

## Reference

Composite of the single-class PoCs in this corpus (crafted-hostile-log,
trojan-source-bidi, homoglyph, alt-screen-hijack, notification-spoof,
osc8-hyperlink-phishing), assembled for the secure-terminal comparison at
https://secure-terminal.github.io/comparison/
