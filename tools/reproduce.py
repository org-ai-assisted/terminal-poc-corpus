#!/usr/bin/env python3
"""Reproduce ONE PoC as a plain file you can render in a THROWAWAY sandbox terminal, to
SEE the effect on a traditional terminal and compare it side by side with
secure-terminal. This is the easy, visual, user-facing path. Firing and DETECTING a
canary automatically is the harness's job (harness/run.py, harness/adversarial.py) --
this helper hands you the file, the right way to feed it, and its risk tier.

The banner and how-to are tailored to the PoC's verification mode -- one size does not
fit all:
  - decoder-crash / denial-of-service are REAL, unmodified payloads that can crash or
    freeze a vulnerable terminal, so they carry a CAUTION, never the SAFE wording;
  - paste-bypass fires only through the PASTE path, not `cat`.
It writes LIVE terminal-attack bytes, so it refuses to run outside a sandbox unless
overridden. See ../SAFETY.md.

    tools/reproduce.py <poc-id> [--out FILE]
    tools/reproduce.py --list
    tools/reproduce.py --self-test   # assert each banner matches its risk tier
"""
import argparse
import binascii
import glob
import os
import re
import shlex
import sys

try:
    import yaml
except ImportError as exc:                                       # pragma: no cover
    sys.stderr.write('poc-corpus: need python3-yaml: %s\n' % exc)
    raise SystemExit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# must equal the schema's id pattern; also blocks path traversal / absolute poc ids.
_ID_RE = re.compile(r'^[a-z0-9]+(-[a-z0-9]+)*$')

# verification modes whose payloads can CRASH / corrupt / FREEZE a vulnerable terminal
# (real, unmodified payloads -- NOT canary-forked, NOT `reset`-recoverable).
_DESTRUCTIVE_MODES = frozenset({'decoder-crash', 'denial-of-service'})


def _confined():
    return (os.environ.get('POC_CORPUS_IN_SANDBOX') == '1'
            or os.environ.get('DIST_AI_IN_SANDBOX') == '1'
            or os.environ.get('GITHUB_ACTIONS') == 'true'
            or os.environ.get('CI') == 'true'
            or os.environ.get('POC_CORPUS_ALLOW_HOST') == '1')


def _decode(payload_hex):
    # identical rule to harness/adversarial.py: strip per-line '#' comments + whitespace
    body = []
    with open(payload_hex, encoding='ascii') as handle:
        for line in handle:
            body.append(''.join(line.split('#', 1)[0].split()))
    return binascii.unhexlify(''.join(body))


def _meta(poc_id):
    # real YAML, so a quoted or inline-commented `verification:` is parsed correctly --
    # a line-split parser would fold the quotes/comment into the mode and mis-tier it.
    try:
        with open(os.path.join(ROOT, 'poc', poc_id, 'meta.yaml'), encoding='utf-8') as fh:
            return yaml.safe_load(fh) or {}
    except OSError:
        return {}


def _mode(meta):
    # default matches the harness: an absent verification field is 'canary-command'.
    return meta.get('verification') or 'canary-command'


def _ids():
    # glob.escape(ROOT): a checkout path containing [ ] * would otherwise be read as a
    # glob pattern and silently match nothing.
    pattern = os.path.join(glob.escape(ROOT), 'poc', '*', 'payload.hex')
    return sorted(os.path.basename(os.path.dirname(p)) for p in glob.glob(pattern))


def _safety_note(mode, out):
    """Per-verification-mode banner + how-to. Destructive classes get a CAUTION;
    paste-bypass is fed via the paste path; all others are cat-and-compare SAFE with the
    harness as the reliable fire/detect path. Command paths are shell-quoted."""
    q = shlex.quote(out)
    if mode in _DESTRUCTIVE_MODES:
        kind = 'a crash/decoder-overflow' if mode == 'decoder-crash' else 'a denial-of-service'
        return (
            'CAUTION: this is a REAL %s payload, NOT a canary fork. It can crash,\n'
            'corrupt, or FREEZE a vulnerable terminal; `reset` may not recover it and you\n'
            'may have to kill the terminal. Run ONLY in a throwaway, disposable sandbox\n'
            'terminal -- never on the host.\n\n'
            'In a THROWAWAY, disposable terminal:\n'
            '  cat %s        # a vulnerable terminal may crash or hang here\n'
            'Then feed the same file to secure-terminal in CLI mode -- it processes it\n'
            'inert, in bounded time, and never runs the decoder.\n' % (kind, q))
    if mode == 'paste-bypass':
        return (
            'SAFE: no destructive action. But this class fires only through the PASTE\n'
            'path -- `cat` sends the bytes as program output, which never enters\n'
            'bracketed-paste mode, so the bypass will NOT trigger from cat. To exercise\n'
            'it, put the bytes on the clipboard and PASTE them into a THROWAWAY terminal:\n'
            '  xclip -selection clipboard < %s    # then Ctrl-Shift-V to paste\n'
            '  reset\n'
            'Then paste the same into secure-terminal -- its paste sanitizer strips the\n'
            'escape, so the guard cannot be broken.\n' % q)
    return (
        'SAFE: this class touches display / input / clipboard / notification state only\n'
        'and carries no destructive action. `reset` restores the terminal DISPLAY\n'
        '(charset, colour, cursor, alt-screen); a hijacked window/tab TITLE or an\n'
        "overwritten CLIPBOARD is external state `reset` does NOT undo -- clear a title\n"
        "with  printf '\\033]0;\\007'  and re-copy to replace the clipboard (or just use a\n"
        'throwaway terminal you discard).\n\n'
        'SEE the difference (in a THROWAWAY terminal):\n'
        '  cat %s          # a traditional terminal renders the attack\n'
        '  reset            # restores the display\n'
        'Then feed the same file to secure-terminal in CLI mode -- it renders it inert.\n\n'
        'To verify neutralization automatically -- for THIS mode and every other -- run\n'
        'the sandbox harness against secure-terminal (no terminal-under-test needed):\n'
        '  POC_CORPUS_IN_SANDBOX=1 harness/adversarial.py\n' % q)


def _self_test():
    """Assert the banner never mislabels a destructive PoC as SAFE, across every PoC.
    A destructive class (decoder-crash / denial-of-service) must get the CAUTION banner
    and never the SAFE wording; every other class must get SAFE. Guards against a future
    crash/DoS PoC inheriting the reset-recoverable claim."""
    failures = 0
    ids = _ids()
    for poc_id in ids:
        mode = _mode(_meta(poc_id))
        note = _safety_note(mode, poc_id + '.payload')
        destructive = mode in _DESTRUCTIVE_MODES
        bad = []
        if destructive and ('CAUTION' not in note or 'SAFE:' in note):
            bad.append('destructive mode not cautioned')
        if not destructive and ('SAFE:' not in note or 'CAUTION' in note):
            bad.append('safe mode not labelled SAFE')
        if bad:
            failures += 1
            print('FAIL   %-34s [%s] %s' % (poc_id, mode, '; '.join(bad)))
        else:
            print('ok     %-34s [%s] %s' % (poc_id, mode,
                                            'CAUTION' if destructive else 'SAFE'))
    print('-- %d PoC(s) checked; %d banner mislabelled' % (len(ids), failures))
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(
        description='Reproduce one PoC as a render-able file (sandbox only).')
    parser.add_argument('poc_id', nargs='?', help='PoC id (see --list)')
    parser.add_argument('--out', default=None, help='output file (default <id>.payload)')
    parser.add_argument('--list', action='store_true', help='list PoC ids and exit')
    parser.add_argument('--self-test', action='store_true',
                        help='assert every PoC banner matches its risk tier, then exit')
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    if args.list or not args.poc_id:
        sys.stdout.write('\n'.join(_ids()) + '\n')
        return 0

    if not _ID_RE.match(args.poc_id):
        sys.stderr.write('invalid PoC id %r (expected a slug like alt-screen-hijack). '
                         'Run --list for the ids.\n' % args.poc_id)
        return 2

    hex_path = os.path.join(ROOT, 'poc', args.poc_id, 'payload.hex')
    if not os.path.isfile(hex_path):
        sys.stderr.write('unknown PoC %r. Run --list for the ids.\n' % args.poc_id)
        return 2

    if not _confined():
        sys.stderr.write(
            'refuse: this writes LIVE terminal-attack bytes. Run it only in a throwaway\n'
            'sandbox terminal. Set POC_CORPUS_IN_SANDBOX=1 (or POC_CORPUS_ALLOW_HOST=1 to\n'
            'override on the host at your own risk). See %s/SAFETY.md.\n' % ROOT)
        return 3

    payload = _decode(hex_path)
    out = args.out or (args.poc_id + '.payload')
    with open(out, 'wb') as handle:
        handle.write(payload)

    meta = _meta(args.poc_id)
    sys.stderr.write(
        'wrote %s (%d bytes) -- PoC %r [%s]\n'
        '  %s\n\n'
        '%s'
        % (out, len(payload), args.poc_id, meta.get('class', ''),
           meta.get('title', ''), _safety_note(_mode(meta), out)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
