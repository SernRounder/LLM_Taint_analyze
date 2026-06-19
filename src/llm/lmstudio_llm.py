"""
src/llm/lmstudio_llm.py – LM Studio (local OpenAI-compatible) LLM provider.

LM Studio exposes an OpenAI-compatible HTTP API at ``http://localhost:1234/v1``
by default.  No API key is required for local usage.

Optional constructor kwargs / environment variables:
    base_url   – LM Studio server URL (default: http://localhost:1234/v1,
                  overridden by LMSTUDIO_BASE_URL)
    model      – model identifier as shown in LM Studio (default: "local-model")
    api_key    – dummy key passed to satisfy the openai client (default: "lm-studio")
"""

from __future__ import annotations

import os

from src.llm.base import BaseLLM

_DEFAULT_BASE_URL = 'http://localhost:1234/v1'
_DEFAULT_MODEL = 'local-model'


class LMStudioLLM(BaseLLM):
    """LM Studio provider using the OpenAI-compatible REST endpoint."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str = 'lm-studio',
        **kwargs,
    ) -> None:
        try:
            import openai  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                'openai package is required for LMStudio provider.  '
                'Run: pip install openai'
            ) from exc

        resolved_url = (
            base_url
            or os.environ.get('LMSTUDIO_BASE_URL', _DEFAULT_BASE_URL)
        )
        resolved_model = model or os.environ.get('LMSTUDIO_MODEL', _DEFAULT_MODEL)

        self._client = openai.OpenAI(api_key=api_key, base_url=resolved_url)
        self._model = resolved_model

    def chat(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[{'role': 'user', 'content': prompt}],
        )
        return response.choices[0].message.content or ''
