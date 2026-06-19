"""
src/llm/gemini_llm.py – Google Gemini LLM provider.

Required environment variable / constructor kwarg:
    api_key   – Google AI API key (falls back to GOOGLE_API_KEY env var).

Optional:
    model     – model name (default: "gemini-1.5-flash")
"""

from __future__ import annotations

import os

from src.llm.base import BaseLLM


class GeminiLLM(BaseLLM):
    """Gemini provider backed by the ``google-generativeai`` package."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = 'gemini-1.5-flash',
        **kwargs,
    ) -> None:
        try:
            import google.generativeai as genai  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                'google-generativeai package is required for Gemini provider.  '
                'Run: pip install google-generativeai'
            ) from exc

        resolved_key = api_key or os.environ.get('GOOGLE_API_KEY', '')
        if not resolved_key:
            raise ValueError(
                'Google API key not provided.  Set GOOGLE_API_KEY or pass api_key=...'
            )

        genai.configure(api_key=resolved_key)
        self._model = genai.GenerativeModel(model)

    def chat(self, prompt: str) -> str:
        response = self._model.generate_content(prompt)
        return response.text or ''
