"""
src/llm/base.py – Abstract base class for all LLM providers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseLLM(ABC):
    """Minimal interface that every LLM provider must implement."""

    @abstractmethod
    def chat(self, prompt: str) -> str:
        """Send *prompt* to the model and return the text response.

        Parameters
        ----------
        prompt:
            The full prompt string to send (system + user messages may be
            combined by the subclass as appropriate).

        Returns
        -------
        str
            The model's text response.

        Raises
        ------
        RuntimeError
            On API / network errors.
        """

    def analyze_function(self, code: str, custom_prompt: str | None = None) -> str:
        """Convenience wrapper: build a taint-analysis prompt and call ``chat``.

        Parameters
        ----------
        code:
            Decompiled pseudo-C source of the function.
        custom_prompt:
            If provided, prepended to the standard prompt template.

        Returns
        -------
        str
            Raw LLM response text.
        """
        base_prompt = custom_prompt or (
            'You are a binary security analyst specializing in taint analysis.\n'
            'For the following decompiled function:\n'
            '1. Determine whether it can act as a **source** of untrusted data '
            '(e.g. reads user input, network data, environment variables).\n'
            '2. Determine whether it can act as a **sink** where untrusted data '
            'could cause a security vulnerability '
            '(e.g. system(), exec(), strcpy(), SQL query, file write).\n'
            '3. Briefly summarise what the function does.\n\n'
            'Respond with valid JSON with keys: '
            '"is_source" (bool), "is_sink" (bool), "summary" (string).\n\n'
            'Function:\n'
        )
        full_prompt = base_prompt + code
        return self.chat(full_prompt)
