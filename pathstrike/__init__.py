"""PathStrike — AD Attack Path Automation via BloodHound CE."""

import os as _os
import sys as _sys

__version__ = "0.1.0"


def _ensure_interpreter_bin_on_path() -> None:
    """Make console-scripts installed alongside the running interpreter
    resolvable via ``PATH`` (and therefore via ``shutil.which`` and any
    subprocess spawn).

    When PathStrike is launched from a virtualenv (``.venv/bin/pathstrike``)
    the venv's ``bin`` directory is normally *not* on ``PATH`` unless the venv
    was "activated".  Tools that were ``pip``-installed into that same venv —
    notably ``bloodyAD`` — then fail to resolve even though they are sitting
    right next to the interpreter, breaking every handler that shells out to
    them.  The directory is *appended* (not prepended) on purpose: system
    tools already on PATH keep priority, and — crucially — the venv's
    ``python3`` does NOT shadow the system ``python3`` for external wrapper
    scripts whose ``#!/usr/bin/env python3`` (or ``exec python3 …``) shebang
    would otherwise pick up the venv interpreter, which lacks those scripts'
    dependencies (e.g. ``coercer`` needs ``sectools``, absent from the venv).
    Appending still lets ``shutil.which``/subprocess find venv-only tools like
    bloodyAD, since nothing earlier on PATH provides them.
    """
    bindir = _os.path.dirname(_os.path.abspath(_sys.executable))
    if not bindir:
        return
    path = _os.environ.get("PATH", "")
    entries = path.split(_os.pathsep) if path else []
    if bindir not in entries:
        _os.environ["PATH"] = _os.pathsep.join([*entries, bindir]) if entries else bindir


_ensure_interpreter_bin_on_path()
