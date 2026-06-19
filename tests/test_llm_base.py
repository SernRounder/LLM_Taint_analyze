"""
tests/test_llm_base.py – unit tests for the LLM base class prompt helper
and the analyze.py JSON response parser.
"""

from __future__ import annotations

import json
import sys
import types
import unittest.mock as mock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_llm(response: str):
    """Return a BaseLLM subclass whose ``chat`` always returns *response*."""
    import importlib
    base_mod = importlib.import_module('src.llm.base')
    BaseLLM = base_mod.BaseLLM

    class MockLLM(BaseLLM):
        def chat(self, prompt: str) -> str:
            return response

    return MockLLM()


# ---------------------------------------------------------------------------
# Tests: BaseLLM.analyze_function
# ---------------------------------------------------------------------------

class TestBaseLLMAnalyzeFunction:
    def test_default_prompt_contains_code(self):
        captured = {}
        import importlib
        base_mod = importlib.import_module('src.llm.base')
        BaseLLM = base_mod.BaseLLM

        class CaptureLLM(BaseLLM):
            def chat(self, prompt: str) -> str:
                captured['prompt'] = prompt
                return '{}'

        llm = CaptureLLM()
        code = 'int main() { return 0; }'
        llm.analyze_function(code)
        assert code in captured['prompt']

    def test_custom_prompt_replaces_default(self):
        captured = {}
        import importlib
        base_mod = importlib.import_module('src.llm.base')
        BaseLLM = base_mod.BaseLLM

        class CaptureLLM(BaseLLM):
            def chat(self, prompt: str) -> str:
                captured['prompt'] = prompt
                return '{}'

        llm = CaptureLLM()
        llm.analyze_function('code here', custom_prompt='MY_CUSTOM_PREFIX\n')
        assert captured['prompt'].startswith('MY_CUSTOM_PREFIX')

    def test_returns_chat_result(self):
        llm = _make_mock_llm('{"is_source": true, "is_sink": false, "summary": "x"}')
        result = llm.analyze_function('void f() {}')
        assert 'is_source' in result


# ---------------------------------------------------------------------------
# Tests: analyze.py _parse_llm_response
# ---------------------------------------------------------------------------

def _parse(raw: str):
    import importlib
    mod = importlib.import_module('analyze')
    return mod._parse_llm_response(raw)


class TestParseLLMResponse:
    def test_valid_json_source(self):
        raw = '{"is_source": true, "is_sink": false, "summary": "reads stdin"}'
        is_source, is_sink = _parse(raw)
        assert is_source is True
        assert is_sink is False

    def test_valid_json_sink(self):
        raw = '{"is_source": false, "is_sink": true, "summary": "calls system()"}'
        is_source, is_sink = _parse(raw)
        assert is_source is False
        assert is_sink is True

    def test_markdown_fence_stripped(self):
        raw = '```json\n{"is_source": true, "is_sink": true, "summary": "x"}\n```'
        is_source, is_sink = _parse(raw)
        assert is_source is True
        assert is_sink is True

    def test_invalid_json_returns_false_false(self):
        is_source, is_sink = _parse('not json at all')
        assert is_source is False
        assert is_sink is False

    def test_empty_string_returns_false_false(self):
        is_source, is_sink = _parse('')
        assert is_source is False
        assert is_sink is False

    def test_missing_keys_default_false(self):
        raw = '{"summary": "just a helper"}'
        is_source, is_sink = _parse(raw)
        assert is_source is False
        assert is_sink is False


# ---------------------------------------------------------------------------
# Tests: src/llm/__init__.py get_llm factory
# ---------------------------------------------------------------------------

class TestGetLLMFactory:
    def test_unknown_provider_raises_value_error(self):
        import importlib
        llm_pkg = importlib.import_module('src.llm')
        try:
            llm_pkg.get_llm('nonexistent_provider')
            assert False, 'Expected ValueError'
        except ValueError as exc:
            assert 'nonexistent_provider' in str(exc)

    def test_known_providers_listed(self):
        import importlib
        llm_pkg = importlib.import_module('src.llm')
        try:
            llm_pkg.get_llm('bad')
        except ValueError as exc:
            msg = str(exc)
        assert 'gpt' in msg
        assert 'gemini' in msg
        assert 'lmstudio' in msg
        assert 'ollama' in msg
