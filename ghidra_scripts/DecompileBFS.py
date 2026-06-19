# DecompileBFS.py – Ghidra headless script for BFS decompilation
#
# Run via analyzeHeadless:
#   analyzeHeadless <project_dir> <project_name> \
#       -import <binary> \
#       -postScript DecompileBFS.py <entry_address> <max_depth> <output_json> [<max_functions>]
#
# Arguments (passed as script args):
#   args[0]  – entry address in hex (e.g. "0x00401000")
#   args[1]  – BFS max depth (integer, e.g. "3")
#   args[2]  – output JSON file path
#   args[3]  – (optional) max number of functions to decompile (default: 500)
#              Hard cap to keep analysis tractable on large (~100 MB) binaries.
#
# Output JSON format:
#   [
#     {
#       "function_name": "main",
#       "address": "0x00401000",
#       "decompiled_code": "...",
#       "callees": ["0x00401100", "0x00401200"]
#     },
#     ...
#   ]

import json
import os
from collections import deque

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def get_function_at_address(address_string):
    """Return the Ghidra Function at *address_string* (hex), or None."""
    addr = currentProgram.getAddressFactory().getAddress(address_string)
    if addr is None:
        return None
    return getFunctionAt(addr)


def decompile_function(decomp_iface, func, monitor):
    """Return decompiled pseudo-C source for *func* as a string."""
    result = decomp_iface.decompileFunction(func, 60, monitor)
    if result is None or not result.decompileCompleted():
        return ''
    markup = result.getDecompiledFunction()
    if markup is None:
        return ''
    return str(markup.getC())


def get_callees(func):
    """Return a list of hex-address strings for functions called by *func*."""
    called_funcs = func.getCalledFunctions(monitor)
    return [hex(int(str(cf.getEntryPoint()), 16)) for cf in called_funcs]


def run():
    args = getScriptArgs()
    if len(args) < 3:
        print('[DecompileBFS] Usage: DecompileBFS.py <entry_addr> <max_depth> <output_json> [<max_functions>]')
        return

    entry_addr_str = args[0]
    max_depth = int(args[1])
    output_path = args[2]
    max_functions = int(args[3]) if len(args) >= 4 else 500

    # Initialise the decompiler
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    task_monitor = ConsoleTaskMonitor()

    visited = {}   # address_str -> record
    queue = deque()  # (func, depth)

    entry_func = get_function_at_address(entry_addr_str)
    if entry_func is None:
        print('[DecompileBFS] No function found at {}'.format(entry_addr_str))
        return

    entry_addr_norm = hex(int(str(entry_func.getEntryPoint()), 16))
    queue.append((entry_func, 0))

    while queue:
        func, depth = queue.popleft()
        addr_norm = hex(int(str(func.getEntryPoint()), 16))

        if addr_norm in visited:
            continue

        # Hard cap: stop collecting new functions once the limit is reached.
        # This keeps analysis tractable for large binaries with many functions.
        if len(visited) >= max_functions:
            print(
                '[DecompileBFS] Reached max_functions limit ({}). '
                'Stopping BFS.'.format(max_functions)
            )
            break

        print('[DecompileBFS] depth={}  {}  {}'.format(depth, func.getName(), addr_norm))

        code = decompile_function(decomp, func, task_monitor)
        callees = get_callees(func)

        visited[addr_norm] = {
            'function_name': str(func.getName()),
            'address': addr_norm,
            'decompiled_code': code,
            'callees': callees,
        }

        if depth < max_depth:
            for callee_addr in callees:
                callee_func = get_function_at_address(callee_addr)
                if callee_func is not None and callee_addr not in visited:
                    queue.append((callee_func, depth + 1))

    decomp.closeProgram()

    records = list(visited.values())
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, 'w') as fh:
        json.dump(records, fh, indent=2)

    print('[DecompileBFS] Wrote {} function(s) to {}'.format(len(records), output_path))


run()
