"""
src/llm/ollama_llm.py – Ollama (local) LLM provider.

Ollama runs a local REST API, by default at ``http://localhost:11434``.

Optional constructor kwargs / environment variables:
    base_url  – Ollama server URL
                (default: http://localhost:11434, overridden by OLLAMA_BASE_URL)
    model     – model tag (default: "llama3", overridden by OLLAMA_MODEL)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from src.llm.base import BaseLLM

_DEFAULT_BASE_URL = 'http://localhost:11434'
_DEFAULT_MODEL = 'llama3'


class OllamaLLM(BaseLLM):
    """Ollama provider using the native ``/api/generate`` REST endpoint.

    This implementation uses only the standard library so that no extra
    packages beyond ``pymongo`` are required for local usage.
    """

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        **kwargs,
    ) -> None:
        self._base_url = (
            base_url or os.environ.get('OLLAMA_BASE_URL', _DEFAULT_BASE_URL)
        ).rstrip('/')
        self._model = model or os.environ.get('OLLAMA_MODEL', _DEFAULT_MODEL)

    def chat(self, prompt: str) -> str:
        url = f'{self._base_url}/api/generate'
        payload = json.dumps({
            'model': self._model,
            'prompt': prompt,
            'stream': False,
        }).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f'Failed to reach Ollama at {self._base_url}: {exc}'
            ) from exc

        return body.get('response', '')
