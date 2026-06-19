"""
tests/test_analyze_cli.py – unit tests for analyze.py argument parsing
and the scoped-analysis wiring (_run_decompilation signature).
"""

from __future__ import annotations

import importlib
import sys
import unittest.mock as mock


def _build_parser():
    mod = importlib.import_module('analyze')
    return mod._build_parser()


class TestAnalyzeParserDefaults:
    def test_max_functions_default(self):
        parser = _build_parser()
        args = parser.parse_args(['uid123', '0x401000'])
        assert args.max_functions == 500

    def test_max_depth_default(self):
        parser = _build_parser()
        args = parser.parse_args(['uid123', '0x401000'])
        assert args.max_depth == 3

    def test_no_ghidra_analysis_default_false(self):
        parser = _build_parser()
        args = parser.parse_args(['uid123', '0x401000'])
        assert args.no_ghidra_analysis is False

    def test_llm_batch_size_default(self):
        parser = _build_parser()
        args = parser.parse_args(['uid123', '0x401000'])
        assert args.llm_batch_size == 50

    def test_provider_default(self):
        parser = _build_parser()
        args = parser.parse_args(['uid123', '0x401000'])
        assert args.provider == 'ollama'


class TestAnalyzeParserCustomValues:
    def test_max_functions_custom(self):
        parser = _build_parser()
        args = parser.parse_args(['uid123', '0x401000', '--max-functions', '200'])
        assert args.max_functions == 200

    def test_no_ghidra_analysis_flag(self):
        parser = _build_parser()
        args = parser.parse_args(['uid123', '0x401000', '--no-ghidra-analysis'])
        assert args.no_ghidra_analysis is True

    def test_llm_batch_size_custom(self):
        parser = _build_parser()
        args = parser.parse_args(['uid123', '0x401000', '--llm-batch-size', '10'])
        assert args.llm_batch_size == 10

    def test_provider_gpt(self):
        parser = _build_parser()
        args = parser.parse_args(['uid123', '0x401000', '--provider', 'gpt'])
        assert args.provider == 'gpt'

    def test_skip_decompile_and_skip_llm(self):
        parser = _build_parser()
        args = parser.parse_args(
            ['uid123', '0x401000', '--skip-decompile', '--skip-llm']
        )
        assert args.skip_decompile is True
        assert args.skip_llm is True
