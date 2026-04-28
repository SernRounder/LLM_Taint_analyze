"""
src/ghidra_runner.py – Python wrapper that invokes Ghidra's analyzeHeadless
and collects the BFS decompilation results.

Environment variables
---------------------
GHIDRA_HEADLESS_PATH
    Full path to the ``analyzeHeadless`` (Linux/macOS) or
    ``analyzeHeadless.bat`` (Windows) script.
    Default: ``/opt/ghidra/support/analyzeHeadless``

Notes on large binaries (~100 MB / tens of thousands of functions)
------------------------------------------------------------------
* Set ``max_functions`` (default 500) to cap the total number of functions
  decompiled during BFS.  The entry function always counts as depth 0.
* Set ``no_analysis=True`` to pass ``-noanalysis`` to Ghidra, skipping the
  full auto-analysis pass.  This drastically reduces startup time for large
  binaries at the cost of potentially incomplete function discovery.  Use it
  when Ghidra's analysis has already been cached in a reusable project directory.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_DEFAULT_HEADLESS = '/opt/ghidra/support/analyzeHeadless'
_SCRIPTS_DIR = Path(__file__).parent.parent / 'ghidra_scripts'


def _headless_path() -> str:
    return os.environ.get('GHIDRA_HEADLESS_PATH', _DEFAULT_HEADLESS)


def run_bfs_decompile(
    binary_path: str | Path,
    entry_address: str,
    max_depth: int = 3,
    max_functions: int = 500,
    no_analysis: bool = False,
    ghidra_project_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Run Ghidra headless on *binary_path* and return BFS decompilation results.

    Parameters
    ----------
    binary_path:
        Path to the firmware/ELF/PE binary on disk.
    entry_address:
        Hex address string where BFS starts (e.g. ``"0x00401000"``).
    max_depth:
        Maximum BFS depth.  A depth of 0 decompiles only the entry function.
    max_functions:
        Hard cap on the total number of functions to decompile.  BFS stops
        as soon as this many unique functions have been collected, regardless
        of depth.  Defaults to 500 to keep analysis tractable for large
        binaries (~100 MB with tens of thousands of functions).
    no_analysis:
        When ``True``, pass ``-noanalysis`` to Ghidra to skip the full
        auto-analysis pass.  Speeds up large-binary imports significantly;
        use when you already have an existing analysed project or when
        minimal function discovery is acceptable.
    ghidra_project_dir:
        Directory for Ghidra's temporary project files.  A fresh ``tmpdir``
        is created if not provided.

    Returns
    -------
    list[dict]
        List of function records as produced by ``DecompileBFS.py``.

    Raises
    ------
    FileNotFoundError
        If the Ghidra headless binary is not found.
    subprocess.CalledProcessError
        If Ghidra exits with a non-zero status.
    """
    headless = _headless_path()
    if not Path(headless).is_file():
        raise FileNotFoundError(
            f'Ghidra analyzeHeadless not found at {headless!r}.  '
            'Set GHIDRA_HEADLESS_PATH or install Ghidra.'
        )

    binary_path = Path(binary_path)

    with tempfile.TemporaryDirectory() as tmpdir:
        project_dir = Path(ghidra_project_dir) if ghidra_project_dir else Path(tmpdir)
        output_json = Path(tmpdir) / 'bfs_result.json'
        project_name = 'taint_analyze_tmp'

        cmd = [
            headless,
            str(project_dir),
            project_name,
            '-import', str(binary_path),
        ]

        if no_analysis:
            cmd.append('-noanalysis')

        cmd += [
            '-scriptPath', str(_SCRIPTS_DIR),
            '-postScript', 'DecompileBFS.py',
            entry_address,
            str(max_depth),
            str(output_json),
            str(max_functions),
            '-deleteProject',
        ]

        subprocess.run(cmd, check=True, capture_output=False)

        if not output_json.exists():
            raise RuntimeError(
                f'DecompileBFS.py did not produce output at {output_json}'
            )

        with open(output_json) as fh:
            return json.load(fh)
