"""
src/llm/openai_llm.py – GPT (OpenAI) LLM provider.

Required environment variable / constructor kwarg:
    api_key   – OpenAI API key (falls back to OPENAI_API_KEY env var).

Optional:
    model     – model name (default: "gpt-4o-mini")
    base_url  – override the API base URL (useful for proxies)
"""

from __future__ import annotations

import os

from src.llm.base import BaseLLM


class OpenAILLM(BaseLLM):
    """GPT provider backed by the ``openai`` Python package."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = 'gpt-4o-mini',
        base_url: str | None = None,
        **kwargs,
    ) -> None:
        try:
            import openai  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                'openai package is required for GPT provider.  '
                'Run: pip install openai'
            ) from exc

        resolved_key = api_key or os.environ.get('OPENAI_API_KEY', '')
        if not resolved_key:
            raise ValueError(
                'OpenAI API key not provided.  Set OPENAI_API_KEY or pass api_key=...'
            )

        client_kwargs: dict = {'api_key': resolved_key}
        if base_url:
            client_kwargs['base_url'] = base_url

        self._client = openai.OpenAI(**client_kwargs)
        self._model = model

    def chat(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[{'role': 'user', 'content': prompt}],
        )
        return response.choices[0].message.content or ''
