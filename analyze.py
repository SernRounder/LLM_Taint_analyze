#!/usr/bin/env python3
"""
analyze.py – Main CLI for the LLM taint-analysis pipeline.

Pipeline
--------
1. Fetch the firmware binary from MongoDB (via fetch_binary) **or** read it
   directly from a local file with ``--binary-file`` (no MongoDB required).
2. Run Ghidra headless BFS decompilation starting at *entry_address*.
3. Store all decompiled function records (MongoDB or in-memory).
4. Call the selected LLM on each function to identify sources / sinks.
5. DFS taint-flow search: find every simple source→sink path in the
   call-graph; store paths in a dedicated database (one DB per binary,
   collection named after the binary).
6. Call the LLM once per discovered path to produce a flow-level summary
   (severity, description, mitigation) and persist it.

MongoDB-free local mode
-----------------------
When ``--binary-file`` is provided **and** ``--mongo-uri`` is not given,
the pipeline automatically switches to an in-memory backend – no MongoDB
installation is required.  Use ``--output-json`` to save the analysis
results to a JSON file instead.

Example (fully local, no MongoDB)::

    python analyze.py my_binary 0x00401000 \\
        --binary-file /path/to/firmware.elf \\
        --output-json results.json

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
    uid              Label / identifier for this binary.  When using
                     ``--binary-file`` without MongoDB, this can be any
                     short name (e.g. the filename stem).
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
    --flow-prompt        Custom prompt prefix for LLM taint-flow analysis.
    --flow-prompt-file   Path to a file whose contents are used as the flow prompt.
    --flow-db-prefix     Prefix for the per-binary taint-flow database name
                         (default: taint_flow).
    --mongo-uri          MongoDB connection URI.  When omitted together with
                         ``--binary-file``, local in-memory storage is used.
    --db-name            Analysis database name.
    --binary-db-name     Database name for the binary GridFS store.
    --skip-decompile     Skip the Ghidra step; assume decompiled data already in DB.
    --skip-llm           Skip the LLM step; only run decompilation.
    --skip-flow          Skip the taint-flow DFS + LLM step.
    --binary-file        Path to a local binary file (skips MongoDB fetch).
                         When combined with no ``--mongo-uri``, the entire
                         pipeline runs without MongoDB.
    --output-json        Path to write analysis results as JSON (functions +
                         taint-flow paths).  Useful in local mode.

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
    p.add_argument(
        'uid',
        help=(
            'Label / identifier for this binary.  When MongoDB is used this '
            'must be the FACT UID.  In local mode (--binary-file without '
            '--mongo-uri) any short name such as the filename stem is fine.'
        ),
    )
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
    p.add_argument('--skip-flow', action='store_true',
                   help='Skip the taint-flow DFS + LLM step.')
    p.add_argument(
        '--flow-prompt', default=None,
        help='Custom prompt prefix for LLM taint-flow path analysis.',
    )
    p.add_argument(
        '--flow-prompt-file', default=None,
        help='File containing the custom LLM prompt for taint-flow analysis.',
    )
    p.add_argument(
        '--flow-db-prefix', default=None,
        help=(
            'Prefix for the per-binary taint-flow MongoDB database name '
            '(default: taint_flow).  The actual DB will be named '
            '"<prefix>_<sanitised_uid>".'
        ),
    )
    p.add_argument('--binary-file', default=None,
                   help=(
                       'Path to a local binary file.  Skips MongoDB GridFS fetch.  '
                       'When --mongo-uri is also omitted, the entire pipeline runs '
                       'without MongoDB (in-memory local mode).'
                   ))
    p.add_argument(
        '--output-json', default=None, metavar='PATH',
        help=(
            'Write analysis results (functions + taint-flow paths) to this '
            'JSON file.  Especially useful in local mode when no MongoDB is '
            'available to persist results.'
        ),
    )
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


def _load_flow_prompt(args) -> str | None:
    if args.flow_prompt_file:
        path = Path(args.flow_prompt_file)
        if not path.is_file():
            print(f'[ERROR] Flow prompt file not found: {path}', file=sys.stderr)
            sys.exit(1)
        return path.read_text()
    return args.flow_prompt


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
    flow_prompt = _load_flow_prompt(args)

    # ------------------------------------------------------------------
    # 1. Connect to analysis DB
    #
    # Local mode: when --binary-file is given and no --mongo-uri is
    # specified, use the in-memory LocalAnalysisDB so that MongoDB is not
    # required at all.
    # ------------------------------------------------------------------
    local_mode = bool(args.binary_file and not args.mongo_uri)

    if local_mode:
        from src.local_db import LocalAnalysisDB  # noqa: PLC0415
        print('[analyze] Local mode: using in-memory analysis database (no MongoDB).')
        db = LocalAnalysisDB(output_json=args.output_json)
    else:
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
        if not args.skip_flow:
            _run_flow_analysis(uid, db, None, flow_prompt, args, local_mode=local_mode)
        if local_mode:
            db.save_json()
            if args.output_json:
                print(f'[analyze] Results written to {args.output_json}')
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
    else:
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

    # ------------------------------------------------------------------
    # 4. Taint-flow DFS + per-path LLM analysis
    # ------------------------------------------------------------------
    if not args.skip_flow:
        _run_flow_analysis(uid, db, llm, flow_prompt, args, local_mode=local_mode)

    # ------------------------------------------------------------------
    # 5. Persist function results to JSON (local mode)
    # ------------------------------------------------------------------
    if local_mode:
        db.save_json()
        if args.output_json:
            print(f'[analyze] Results written to {args.output_json}')


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
    print(f'[analyze] Stored {len(records)} decompiled function record(s).')


def _run_flow_analysis(uid, db, llm, flow_prompt, args, *, local_mode: bool = False):
    """Stage 4: DFS taint-flow search + per-path LLM analysis."""
    from src.taint_flow import find_taint_paths  # noqa: PLC0415

    print('[analyze] Running taint-flow DFS …')
    all_funcs = db.get_all_functions(uid)
    paths = find_taint_paths(all_funcs)

    if not paths:
        print('[analyze] No source→sink paths found.')
        return

    print(f'[analyze] Found {len(paths)} taint path(s). Storing to flow database …')

    if local_mode:
        from src.local_db import LocalFlowDB  # noqa: PLC0415
        output_json = getattr(args, 'output_json', None)
        # Derive a sibling path for flow results when output_json is set
        flow_output = None
        if output_json:
            p = Path(output_json)
            flow_output = p.parent / (p.stem + '_flows' + p.suffix)
        flow_db = LocalFlowDB(uid=uid, output_json=flow_output)
    else:
        from src.flow_db import FlowDB  # noqa: PLC0415
        flow_db = FlowDB(
            uid=uid,
            mongo_uri=args.mongo_uri,
            flow_db_prefix=args.flow_db_prefix,
        )

    # Attach uid and default flow_llm_result before inserting
    for p in paths:
        p['uid'] = uid
        p.setdefault('flow_llm_result', None)

    inserted = flow_db.insert_paths(paths)
    print(f'[analyze] Stored {inserted} new path record(s).')

    if llm is None:
        print('[analyze] No LLM available for flow analysis (--skip-llm was set).')
        if local_mode:
            flow_db.save_json()
        return

    pending = flow_db.get_unanalyzed_paths()
    if not pending:
        print('[analyze] All paths already have flow LLM results.')
        if local_mode:
            flow_db.save_json()
        return

    print(f'[analyze] Analyzing {len(pending)} path(s) with LLM …')
    for i, path_rec in enumerate(pending, 1):
        src = path_rec['source_address']
        snk = path_rec['sink_address']
        flow = path_rec['taint_flow']
        funcs = path_rec.get('functions', [])
        sink_code = path_rec.get('sink_decompiled', '')

        print(
            f'  [{i}/{len(pending)}] {src} → {snk}  '
            f'({len(flow)} hop(s))',
            end=' ', flush=True,
        )

        try:
            raw = llm.analyze_flow(flow, funcs, sink_code, flow_prompt)
        except Exception as exc:  # noqa: BLE001
            print(f'[WARN] LLM flow error: {exc}')
            raw = ''

        flow_db.update_flow_llm_result(src, snk, flow, raw)
        print('ok')

    print(f'[analyze] Taint-flow analysis complete. Total paths: {flow_db.count_paths()}')

    if local_mode:
        flow_db.save_json()


if __name__ == '__main__':
    main()
