#!/usr/bin/env python3
"""Reproduce ONE PoC as a plain file you can `cat` in a THROWAWAY sandbox terminal, to
see the effect on a traditional terminal and compare with secure-terminal. This is the
easy, user-facing path -- the harness (adversarial.py / run.py) proves neutralization
automatically; this just hands you a file.

SAFE: every corpus payload is canary-forked (a fired attack writes only the marker
POC-CORPUS-CANARY-FIRED) and touches display / clipboard / notification state only --
recover any terminal with `reset`. It still writes LIVE terminal-attack bytes, so it
refuses to run outside a sandbox unless overridden. See ../SAFETY.md.

    tools/reproduce.py <poc-id> [--out FILE]
    tools/reproduce.py --list
    tools/reproduce.py --self-test   # assert each banner matches its risk tier

The safety banner is tailored to the PoC's verification mode: crash/DoS classes
(decoder-crash, denial-of-service) are REAL unmodified payloads that can crash or
freeze a vulnerable terminal, so they carry a CAUTION, never the reset-recoverable
SAFE wording. See SAFETY.md.
"""
import argparse
import binascii
import glob
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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


def _field(meta_path, key):
    try:
        for line in open(meta_path, encoding='utf-8'):
            if line.startswith(key + ':'):
                return line.split(':', 1)[1].strip().strip('"')
    except OSError:
        pass
    return ''


def _ids():
    return sorted(os.path.basename(os.path.dirname(p))
                  for p in glob.glob(os.path.join(ROOT, 'poc', '*', 'payload.hex')))


# verification modes whose payloads can CRASH / corrupt / FREEZE a vulnerable
# terminal (real, unmodified payloads -- NOT canary-forked, NOT `reset`-recoverable).
_DESTRUCTIVE_MODES = frozenset({'decoder-crash', 'denial-of-service'})


def _safety_note(mode, out):
    """Per-verification-mode safety banner. Destructive classes (decoder-crash,
    denial-of-service) can crash/hang a vulnerable terminal and are NOT
    reset-recoverable, so they get an honest caution -- never the SAFE wording."""
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
            'inert, in bounded time, and never runs the decoder.\n' % (kind, out))
    return (
        'SAFE: display / input / clipboard / notification state only, recoverable with\n'
        '`reset`. The payload carries the inert marker POC-CORPUS-CANARY-FIRED, not a\n'
        'real exploit.\n\n'
        'In a THROWAWAY terminal:\n'
        '  cat %s        # a traditional terminal: the attack fires\n'
        '  reset            # recover\n'
        'Then feed the same file to secure-terminal in CLI mode -- it renders it inert.\n'
        % out)


def _self_test():
    """Assert the safety banner never mislabels a destructive PoC as SAFE, across
    every PoC in the corpus. A destructive class (decoder-crash / denial-of-service)
    must get the CAUTION banner and never the SAFE / reset-recoverable wording; every
    other class must get SAFE. Guards against a future crash/DoS PoC inheriting the
    reset-recoverable claim."""
    failures = 0
    for poc_id in _ids():
        mode = _field(os.path.join(ROOT, 'poc', poc_id, 'meta.yaml'), 'verification') \
            or 'canary-command'
        note = _safety_note(mode, poc_id + '.payload')
        destructive = mode in _DESTRUCTIVE_MODES
        bad = []
        if destructive and ('CAUTION' not in note or 'SAFE:' in note
                            or 'reset            # recover' in note):
            bad.append('destructive mode not cautioned')
        if not destructive and ('SAFE:' not in note or 'CAUTION' in note):
            bad.append('safe mode not labelled SAFE')
        if bad:
            failures += 1
            print('FAIL   %-34s [%s] %s' % (poc_id, mode, '; '.join(bad)))
        else:
            tier = 'CAUTION' if destructive else 'SAFE'
            print('ok     %-34s [%s] %s' % (poc_id, mode, tier))
    print('-- %d PoC(s) checked; %d banner mislabelled' % (len(_ids()), failures))
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(
        description='Reproduce one PoC as a cat-able file (sandbox only).')
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

    poc_dir = os.path.join(ROOT, 'poc', args.poc_id)
    hex_path = os.path.join(poc_dir, 'payload.hex')
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

    meta_path = os.path.join(poc_dir, 'meta.yaml')
    # default matches the harness: an absent verification field is 'canary-command'.
    mode = _field(meta_path, 'verification') or 'canary-command'
    sys.stderr.write(
        'wrote %s (%d bytes) -- PoC %r [%s]\n'
        '  %s\n\n'
        '%s'
        % (out, len(payload), args.poc_id,
           _field(meta_path, 'class'), _field(meta_path, 'title'),
           _safety_note(mode, out)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
