"""
tests/test_flow_db_sanitize.py – unit tests for src/flow_db._sanitize_name.
No MongoDB connection required.
"""

from __future__ import annotations

import importlib


def _sanitize(name: str) -> str:
    mod = importlib.import_module('src.flow_db')
    return mod._sanitize_name(name)


class TestSanitizeName:
    def test_plain_hex_uid_unchanged(self):
        uid = 'abcdef1234567890abcdef1234_4'
        result = _sanitize(uid)
        # No prohibited characters; only truncated if >38 chars
        assert result == uid[:38]

    def test_dots_replaced(self):
        assert '.' not in _sanitize('a.b.c')

    def test_spaces_replaced(self):
        assert ' ' not in _sanitize('hello world')

    def test_slashes_replaced(self):
        assert '/' not in _sanitize('path/to/file')
        assert '\\' not in _sanitize('path\\to\\file')

    def test_truncated_to_38(self):
        long_name = 'a' * 100
        assert len(_sanitize(long_name)) == 38

    def test_empty_string_returns_unknown(self):
        assert _sanitize('') == 'unknown'

    def test_only_prohibited_chars_returns_underscores(self):
        result = _sanitize('/\\."$*<>:|?')
        # All prohibited characters should be replaced with underscores
        assert set(result) == {'_'}


class TestAnalyzeFlowInBaseLLM:
    """Smoke-test BaseLLM.analyze_flow prompt construction."""

    def test_flow_prompt_contains_source_and_sink(self):
        captured = {}
        import importlib
        base_mod = importlib.import_module('src.llm.base')
        BaseLLM = base_mod.BaseLLM

        class CaptureLLM(BaseLLM):
            def chat(self, prompt: str) -> str:
                captured['prompt'] = prompt
                return '{}'

        llm = CaptureLLM()
        funcs = [
            {'address': '0x1000', 'function_name': 'source_fn', 'llm_result': ''},
            {'address': '0x2000', 'function_name': 'sink_fn', 'llm_result': ''},
        ]
        llm.analyze_flow(
            taint_flow=['0x1000', '0x2000'],
            functions=funcs,
            sink_decompiled='void sink() {}',
        )
        prompt = captured['prompt']
        assert '0x1000' in prompt
        assert '0x2000' in prompt

    def test_custom_flow_prompt_used(self):
        captured = {}
        import importlib
        base_mod = importlib.import_module('src.llm.base')
        BaseLLM = base_mod.BaseLLM

        class CaptureLLM(BaseLLM):
            def chat(self, prompt: str) -> str:
                captured['prompt'] = prompt
                return '{}'

        llm = CaptureLLM()
        llm.analyze_flow(
            taint_flow=['0x1000', '0x2000'],
            functions=[],
            sink_decompiled='',
            custom_prompt='MY_FLOW_PREFIX\n',
        )
        assert captured['prompt'].startswith('MY_FLOW_PREFIX')


class TestAnalyzeCLIFlowFlags:
    """Verify new flow-related CLI flags are parsed correctly."""

    def _parser(self):
        import importlib
        mod = importlib.import_module('analyze')
        return mod._build_parser()

    def test_skip_flow_default_false(self):
        args = self._parser().parse_args(['uid', '0x1000'])
        assert args.skip_flow is False

    def test_skip_flow_flag(self):
        args = self._parser().parse_args(['uid', '0x1000', '--skip-flow'])
        assert args.skip_flow is True

    def test_flow_db_prefix_default_none(self):
        args = self._parser().parse_args(['uid', '0x1000'])
        assert args.flow_db_prefix is None

    def test_flow_db_prefix_custom(self):
        args = self._parser().parse_args(['uid', '0x1000', '--flow-db-prefix', 'myflows'])
        assert args.flow_db_prefix == 'myflows'

    def test_flow_prompt(self):
        args = self._parser().parse_args(['uid', '0x1000', '--flow-prompt', 'hello'])
        assert args.flow_prompt == 'hello'
