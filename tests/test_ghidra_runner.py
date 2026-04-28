"""
tests/test_ghidra_runner.py – unit tests for src/ghidra_runner.py.

These tests mock subprocess.run so they work without Ghidra installed.
"""

from __future__ import annotations

import json
import os
import unittest.mock as mock
from pathlib import Path


def _runner():
    import importlib
    return importlib.import_module('src.ghidra_runner')


class TestRunBFSDecompileArgBuilding:
    """Verify the Ghidra command-line is built correctly."""

    def _run_with_mock(self, **kwargs):
        """Call run_bfs_decompile with a mocked subprocess and Ghidra binary."""
        runner = _runner()
        sample_output = [
            {
                'function_name': 'main',
                'address': '0x401000',
                'decompiled_code': 'int main() {}',
                'callees': [],
            }
        ]

        with mock.patch.object(Path, 'is_file', return_value=True), \
             mock.patch('subprocess.run') as mock_run, \
             mock.patch('builtins.open', mock.mock_open(
                 read_data=json.dumps(sample_output)
             )), \
             mock.patch.object(Path, 'exists', return_value=True):
            result = runner.run_bfs_decompile(
                binary_path='/tmp/fake.bin',
                entry_address='0x401000',
                **kwargs,
            )
        return mock_run.call_args[0][0], result  # cmd list, returned records

    def test_default_args_in_command(self):
        cmd, records = self._run_with_mock()
        cmd_str = ' '.join(cmd)
        assert 'DecompileBFS.py' in cmd_str
        assert '0x401000' in cmd_str
        # max_depth default = 3
        assert '3' in cmd_str
        # max_functions default = 500
        assert '500' in cmd_str
        # -noanalysis should NOT be present by default
        assert '-noanalysis' not in cmd_str

    def test_no_analysis_flag(self):
        cmd, _ = self._run_with_mock(no_analysis=True)
        assert '-noanalysis' in cmd

    def test_custom_max_functions(self):
        cmd, _ = self._run_with_mock(max_functions=100)
        cmd_str = ' '.join(cmd)
        assert '100' in cmd_str

    def test_custom_max_depth(self):
        cmd, _ = self._run_with_mock(max_depth=5)
        # The depth value should appear as a script arg
        # Script args come after 'DecompileBFS.py': <entry> <depth> <output> <max_funcs>
        idx = cmd.index('DecompileBFS.py')
        assert cmd[idx + 2] == '5'

    def test_max_functions_passed_as_fourth_script_arg(self):
        cmd, _ = self._run_with_mock(max_functions=123)
        idx = cmd.index('DecompileBFS.py')
        # args: entry(+1), depth(+2), output(+3), max_functions(+4)
        assert cmd[idx + 4] == '123'

    def test_headless_not_found_raises(self):
        runner = _runner()
        with mock.patch.object(Path, 'is_file', return_value=False):
            try:
                runner.run_bfs_decompile('/tmp/x.bin', '0x0')
                assert False, 'Expected FileNotFoundError'
            except FileNotFoundError:
                pass
