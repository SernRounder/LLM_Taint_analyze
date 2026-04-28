#!/usr/bin/env python3
"""
analyze.py – Main CLI for the LLM taint-analysis pipeline.

Pipeline
--------
1. Fetch the firmware binary from MongoDB (via fetch_binary).
2. Run Ghidra headless BFS decompilation starting at *entry_address*.
3. Store all decompiled function records in MongoDB.
4. Call the selected LLM on each function to identify sources / sinks.
5. Persist LLM results back to MongoDB.

Scoped analysis (large-binary support)
---------------------------------------
Target binaries can be very large (~100 MB, tens of thousands of functions).
Only functions reachable from *entry_address* within the BFS horizon are ever
touched:

* ``--max-depth`` (default 3) limits how many call levels are followed.
* ``--max-functions`` (default 500) is a hard cap on the number of unique
  functions decompiled, regardless of depth.  BFS stops as soon as this
  limit is hit.  Raise or lower it to trade thoroughness for speed.
* ``--no-ghidra-analysis`` skips Ghidra's full binary auto-analysis pass,
  which can take hours on large files.  Useful when an existing analysed
  project is being reused or when minimal function discovery is acceptable.

Usage
-----
    python analyze.py <uid> <entry_address> [options]

Positional arguments
    uid              FACT UID of the binary stored in MongoDB.
    entry_address    Hex address of the entry function for BFS
                     (e.g. 0x00401000).

Options
    --max-depth          BFS traversal depth (default: 3).
    --max-functions      Hard cap on functions to decompile (default: 500).
    --no-ghidra-analysis Skip Ghidra's full auto-analysis pass (faster for
                         large binaries; may miss some functions).
    --provider           LLM provider: gpt | gemini | lmstudio | ollama
                         (default: ollama).
    --model              Model name / tag for the chosen provider.
    --prompt             Custom prompt prefix for LLM semantic identification.
    --prompt-file        Path to a file whose contents are used as the custom prompt.
    --llm-batch-size     Process LLM calls N at a time, printing progress per
                         batch (default: 50).
    --mongo-uri          MongoDB connection URI.
    --db-name            Analysis database name.
    --binary-db-name     Database name for the binary GridFS store.
    --skip-decompile     Skip the Ghidra step; assume decompiled data already in DB.
    --skip-llm           Skip the LLM step; only run decompilation.
    --binary-file        Path to a local binary file (skips MongoDB fetch).

Environment variables (all optional)
    EXTERNAL_LLM_PRIMARY_MONGO_URI
    EXTERNAL_LLM_PRIMARY_DB_NAME
    GHIDRA_HEADLESS_PATH
    OPENAI_API_KEY
    GOOGLE_API_KEY
    LMSTUDIO_BASE_URL
    OLLAMA_BASE_URL / OLLAMA_MODEL
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='analyze.py',
        description='LLM-assisted taint analysis via Ghidra BFS decompilation.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('uid', help='FACT UID of the target binary in MongoDB.')
    p.add_argument(
        'entry_address',
        help='Hex entry address for BFS decompilation (e.g. 0x00401000).',
    )
    p.add_argument('--max-depth', type=int, default=3, metavar='N',
                   help='BFS max depth (default: 3).')
    p.add_argument(
        '--max-functions', type=int, default=500, metavar='N',
        help=(
            'Hard cap on the number of unique functions to decompile (default: 500). '
            'BFS stops once this many functions have been collected, regardless of depth. '
            'Increase for more thorough analysis of large binaries; decrease for speed.'
        ),
    )
    p.add_argument(
        '--no-ghidra-analysis', action='store_true',
        help=(
            'Skip Ghidra\'s full binary auto-analysis pass (-noanalysis). '
            'Drastically speeds up import of large (~100 MB) binaries at the cost '
            'of potentially incomplete function discovery.'
        ),
    )
    p.add_argument('--provider', default='ollama',
                   choices=['gpt', 'gemini', 'lmstudio', 'ollama'],
                   help='LLM provider (default: ollama).')
    p.add_argument('--model', default=None,
                   help='Model name/tag for the chosen provider.')
    p.add_argument('--prompt', default=None,
                   help='Custom prompt prefix for LLM semantic identification.')
    p.add_argument('--prompt-file', default=None,
                   help='File containing the custom LLM prompt.')
    p.add_argument(
        '--llm-batch-size', type=int, default=50, metavar='N',
        help=(
            'Number of functions to send to the LLM per progress report (default: 50). '
            'Does not affect correctness; controls how often progress is printed.'
        ),
    )
    p.add_argument('--mongo-uri', default=None,
                   help='MongoDB connection URI.')
    p.add_argument('--db-name', default=None,
                   help='Analysis database name.')
    p.add_argument('--binary-db-name', default=None,
                   help='Database name for the binary GridFS store.')
    p.add_argument('--skip-decompile', action='store_true',
                   help='Skip Ghidra; assume decompiled data is already in DB.')
    p.add_argument('--skip-llm', action='store_true',
                   help='Skip LLM analysis; only run decompilation.')
    p.add_argument('--binary-file', default=None,
                   help='Use a local binary file instead of fetching from MongoDB.')
    return p


# ---------------------------------------------------------------------------
# Helper: load custom prompt
# ---------------------------------------------------------------------------

def _load_prompt(args) -> str | None:
    if args.prompt_file:
        path = Path(args.prompt_file)
        if not path.is_file():
            print(f'[ERROR] Prompt file not found: {path}', file=sys.stderr)
            sys.exit(1)
        return path.read_text()
    return args.prompt


# ---------------------------------------------------------------------------
# Helper: parse LLM JSON response
# ---------------------------------------------------------------------------

def _parse_llm_response(raw: str) -> tuple[bool, bool]:
    """Extract (is_source, is_sink) from the LLM JSON response.

    Falls back to ``(False, False)`` if parsing fails.
    """
    raw = raw.strip()
    # Strip markdown code fences if present
    if raw.startswith('```'):
        lines = raw.splitlines()
        raw = '\n'.join(
            line for line in lines
            if not line.startswith('```')
        ).strip()
    try:
        data = json.loads(raw)
        return bool(data.get('is_source', False)), bool(data.get('is_sink', False))
    except (json.JSONDecodeError, AttributeError):
        return False, False


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    uid = args.uid
    entry_address = args.entry_address
    custom_prompt = _load_prompt(args)

    # ------------------------------------------------------------------
    # 1. Connect to analysis DB
    # ------------------------------------------------------------------
    from src.db import AnalysisDB  # noqa: PLC0415

    print('[analyze] Connecting to analysis database …')
    db = AnalysisDB(mongo_uri=args.mongo_uri, db_name=args.db_name)

    # ------------------------------------------------------------------
    # 2. Ghidra BFS decompilation
    # ------------------------------------------------------------------
    if not args.skip_decompile:
        # Obtain the binary
        if args.binary_file:
            binary_path = Path(args.binary_file)
            if not binary_path.is_file():
                print(f'[ERROR] Binary file not found: {binary_path}', file=sys.stderr)
                sys.exit(1)
            _run_decompilation(
                uid, entry_address, args.max_depth,
                args.max_functions, args.no_ghidra_analysis,
                binary_path, db,
            )
        else:
            # Fetch from MongoDB GridFS
            print(f'[analyze] Fetching binary {uid!r} from MongoDB …')
            from fetch_binary import fetch_binary_bytes  # noqa: PLC0415

            binary_data = fetch_binary_bytes(
                uid,
                mongo_uri=args.mongo_uri,
                db_name=args.binary_db_name,
            )
            if binary_data is None:
                print(f'[ERROR] Binary not found for UID: {uid}', file=sys.stderr)
                sys.exit(1)

            with tempfile.NamedTemporaryFile(
                suffix='.bin', delete=False, dir='/tmp'
            ) as tmp:
                tmp.write(binary_data)
                tmp_path = Path(tmp.name)

            try:
                _run_decompilation(
                    uid, entry_address, args.max_depth,
                    args.max_functions, args.no_ghidra_analysis,
                    tmp_path, db,
                )
            finally:
                tmp_path.unlink(missing_ok=True)
    else:
        print('[analyze] Skipping decompilation (--skip-decompile).')

    # ------------------------------------------------------------------
    # 3. LLM semantic analysis
    # ------------------------------------------------------------------
    if args.skip_llm:
        print('[analyze] Skipping LLM analysis (--skip-llm).')
        return

    print(f'[analyze] Loading LLM provider: {args.provider} …')
    llm_kwargs: dict = {}
    if args.model:
        llm_kwargs['model'] = args.model

    from src.llm import get_llm  # noqa: PLC0415

    llm = get_llm(args.provider, **llm_kwargs)

    functions = db.get_unanalyzed_functions(uid)
    if not functions:
        print('[analyze] All functions already have LLM results; nothing to do.')
        return

    total_funcs = len(functions)
    batch_size = args.llm_batch_size
    print(
        f'[analyze] Analyzing {total_funcs} function(s) with LLM '
        f'(batch_size={batch_size}) …'
    )
    for i, func in enumerate(functions, 1):
        addr = func['address']
        name = func.get('function_name', addr)
        code = func.get('decompiled_code', '')

        print(f'  [{i}/{total_funcs}] {name}  ({addr})', end=' ', flush=True)

        try:
            raw_result = llm.analyze_function(code, custom_prompt)
            is_source, is_sink = _parse_llm_response(raw_result)
        except Exception as exc:  # noqa: BLE001
            print(f'[WARN] LLM error: {exc}')
            raw_result = ''
            is_source, is_sink = False, False

        db.update_llm_result(uid, addr, raw_result, is_source, is_sink)
        tags = []
        if is_source:
            tags.append('SOURCE')
        if is_sink:
            tags.append('SINK')
        print(', '.join(tags) if tags else 'ok')

        if batch_size > 0 and i % batch_size == 0 and i < total_funcs:
            print(
                f'[analyze] Progress: {i}/{total_funcs} functions analyzed '
                f'({i * 100 // total_funcs}%) …'
            )

    total = db.count_functions(uid)
    print(f'[analyze] Done.  {total} function(s) stored for UID {uid!r}.')


def _run_decompilation(uid, entry_address, max_depth, max_functions, no_analysis, binary_path, db):
    from src.ghidra_runner import run_bfs_decompile  # noqa: PLC0415

    print(
        f'[analyze] Running Ghidra BFS decompilation '
        f'(entry={entry_address}, depth={max_depth}, max_functions={max_functions}) …'
    )
    records = run_bfs_decompile(
        binary_path=binary_path,
        entry_address=entry_address,
        max_depth=max_depth,
        max_functions=max_functions,
        no_analysis=no_analysis,
    )
    # Attach UID to every record
    for rec in records:
        rec['uid'] = uid
        rec.setdefault('llm_result', None)
        rec.setdefault('is_source', False)
        rec.setdefault('is_sink', False)

    db.upsert_functions(records)
    print(f'[analyze] Stored {len(records)} decompiled function(s) in MongoDB.')


if __name__ == '__main__':
    main()
