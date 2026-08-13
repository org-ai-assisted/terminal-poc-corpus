#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

"""Corpus-coverage audit (#31 P2): every schema `class` has a LIVE conformance test
whose oracle is a REAL EFFECT of secure-terminal, not a static substring proxy.

Three properties, per schema class:

  1. COVERED -- at least one poc/*/meta.yaml declares the class. A schema class with
     no PoC is an untested attack surface.
  2. WIRED   -- every such PoC's `verification` mode resolves in the adversarial
     harness's _MODES (an unknown mode SKIPs in the harness, i.e. is silently
     untested -- a false green).
  3. REAL-EFFECT, NOT A PROXY -- the class's oracle is proven to measure secure-
     terminal's actual behaviour via a DIFFERENTIAL: its detector FIRES on the
     synthetic VULNERABLE observable (the per-class canary triggers) AND CLEARS when
     driven on secure-terminal's real observable for the PoC (secure-terminal
     neutralized it). A static substring proxy -- one that greps the raw payload and
     ignores what secure-terminal did -- would FIRE on the real payload too (it still
     contains the dangerous bytes), so it fails the "clears on real" half and the
     audit rejects it. This is the structural guarantee that the oracle is not a
     tautology or a proxy, not a hand-maintained annotation that can rot.

`--canary` proves the audit has teeth: it registers a deliberate PROXY oracle (a
detector that greps the raw payload) for a synthetic class and confirms the real-
effect check REJECTS it. A green audit with a passing canary means a class that
regressed to a proxy oracle, or a new schema class with no real oracle, would fail.

CONFINED (feeds live payloads through secure-terminal): runs in the sandbox / CI
only, like the adversarial harness. TRUSTED TOOLING -- needs an ai-review pass before
a CI gate relies on its verdict. Exit 0 iff every class is covered, wired and
real-effect; 1 otherwise; 77 if secure-terminal cannot be located.
"""

import glob
import json
import os
import sys

_HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HARNESS_DIR)
if _HARNESS_DIR not in sys.path:
    sys.path.insert(0, _HARNESS_DIR)

import adversarial as adv          # noqa: E402  (the vetted driving machinery)

try:
    import yaml                                                  # noqa: E402
except Exception as exc:  # pylint: disable=broad-except
    sys.stderr.write('coverage_audit: need python3-yaml: %s\n' % exc)
    raise SystemExit(2)


def _log(msg):
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()


def _schema_classes():
    path = os.path.join(_ROOT, 'schema', 'poc.schema.json')
    with open(path, encoding='utf-8') as handle:
        schema = json.load(handle)
    return schema['properties']['class']['enum']


def _pocs_by_class():
    """{class: [(poc_id, verification_mode), ...]} over every poc/*/meta.yaml."""
    by_class = {}
    for meta_path in sorted(glob.glob(os.path.join(_ROOT, 'poc', '*', 'meta.yaml'))):
        with open(meta_path, encoding='utf-8') as handle:
            meta = yaml.safe_load(handle)
        cls = meta.get('class')
        mode = meta.get('verification', 'canary-command')
        by_class.setdefault(cls, []).append(
            (os.path.basename(os.path.dirname(meta_path)), mode))
    return by_class


def _payload_for(poc_id):
    return adv._decode(os.path.join(_ROOT, 'poc', poc_id, 'payload.hex'))


def _is_real_effect(mode, payload):
    """The differential: the mode's detector must FIRE on the synthetic vulnerable
    observable (its canary triggers) AND CLEAR on secure-terminal's real observable
    for `payload` (secure-terminal neutralized it). Both halves are required, so a
    proxy that ignores the observable (fires on both) is rejected. Returns
    (is_real, fires_on_vulnerable, clears_on_real)."""
    observe, detect = adv._MODES[mode]
    fires_on_vulnerable = bool(detect(adv._vulnerable_observable(mode)))
    clears_on_real = not bool(detect(observe(payload)))
    return (fires_on_vulnerable and clears_on_real,
            fires_on_vulnerable, clears_on_real)


def audit():
    """Run the three properties over every schema class. Returns the failure count."""
    classes = _schema_classes()
    by_class = _pocs_by_class()
    failures = 0

    # (0) no PoC may declare a class the schema does not know (drift the other way).
    for cls in sorted(by_class):
        if cls not in classes:
            _log('FAIL  poc class %r is not in the schema enum' % cls)
            failures += 1

    for cls in classes:
        pocs = by_class.get(cls, [])
        # (1) COVERED
        if not pocs:
            _log('FAIL  %-26s no PoC declares this class (untested surface)' % cls)
            failures += 1
            continue
        # pick a representative PoC (the first, sorted) whose mode is wired.
        rep = None
        for poc_id, mode in pocs:
            # (2) WIRED
            if mode not in adv._MODES:
                _log('FAIL  %-26s PoC %s uses unknown verification mode %r (SKIPs '
                     'in the harness -- a false green)' % (cls, poc_id, mode))
                failures += 1
                continue
            if rep is None:
                rep = (poc_id, mode)
        if rep is None:
            continue                            # every PoC unwired -> already counted
        poc_id, mode = rep
        # (3) REAL-EFFECT, NOT A PROXY
        real, fires, clears = _is_real_effect(mode, _payload_for(poc_id))
        if real:
            _log('ok    %-26s [%s] real-effect oracle (fires on vulnerable, clears '
                 'on secure-terminal) via %s' % (cls, mode, poc_id))
        else:
            why = ('the canary does NOT fire on the vulnerable case (tautology)'
                   if not fires else
                   'the detector STILL fires on secure-terminal\'s real output -- a '
                   'static substring proxy, not a real-effect oracle')
            _log('FAIL  %-26s [%s] %s (via %s)' % (cls, mode, why, poc_id))
            failures += 1
    return failures


def canary():
    """Prove the real-effect check REJECTS a proxy oracle. Register a synthetic
    verification mode whose detector greps the RAW payload (ignoring what secure-
    terminal did) -- exactly the proxy the audit must catch -- and confirm
    _is_real_effect reports it as NOT real-effect."""
    mode = '__canary_proxy__'
    # observable: hand the detector the raw payload UNCHANGED (no secure-terminal).
    # detector: a static substring grep for an escape byte -> fires on any payload
    # carrying one, whether or not secure-terminal neutralized it.
    adv._MODES[mode] = (lambda payload: payload.decode('latin-1'),
                        lambda text: '\x1b' in text)
    adv._vulnerable_observable_orig = adv._vulnerable_observable

    def _vuln(m):
        if m == mode:
            return 'log\x1bX'                   # a surviving escape -> the proxy fires
        return adv._vulnerable_observable_orig(m)
    adv._vulnerable_observable = _vuln
    try:
        payload = b'log\x1b[?1049hPOC'          # carries an escape secure-terminal strips
        real, fires, clears = _is_real_effect(mode, payload)
        # the proxy FIRES on the vulnerable case but ALSO still fires on the raw
        # payload (it never ran secure-terminal), so clears_on_real is False and it
        # is NOT real-effect. If the audit called this real, it would be blind to a
        # proxy regression.
        ok = fires and not clears and not real
        _log('%s  canary: a proxy oracle is %s (fires=%s clears=%s)'
             % ('PASS' if ok else 'FAIL',
                'REJECTED as not real-effect' if ok else 'WRONGLY ACCEPTED',
                fires, clears))
        return 0 if ok else 1
    finally:
        del adv._MODES[mode]
        adv._vulnerable_observable = adv._vulnerable_observable_orig


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--canary', action='store_true',
                        help='prove the real-effect check rejects a proxy oracle, then exit')
    args = parser.parse_args(argv)

    adv.require_confined()
    if not adv.ST_PKG:
        _log('coverage_audit: SKIP (secure-terminal not found; set SECURE_TERMINAL_REPO)')
        return 77
    if args.canary:
        return canary()

    _log('== corpus-coverage audit: every schema class has a real-effect oracle ==')
    failures = audit()
    # the canary runs every time too, so a toothless check can never pass silently.
    canary_rc = canary()
    classes = _schema_classes()
    _log('-- %d schema class(es); %d audit failure(s); canary %s'
         % (len(classes), failures, 'OK' if canary_rc == 0 else 'BROKEN'))
    return 0 if (failures == 0 and canary_rc == 0) else 1


if __name__ == '__main__':
    sys.exit(main())
