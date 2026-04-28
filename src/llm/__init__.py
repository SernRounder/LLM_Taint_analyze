"""
src/llm/__init__.py – LLM provider factory.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.llm.base import BaseLLM

_PROVIDERS: dict[str, str] = {
    'gpt': 'src.llm.openai_llm.OpenAILLM',
    'gemini': 'src.llm.gemini_llm.GeminiLLM',
    'lmstudio': 'src.llm.lmstudio_llm.LMStudioLLM',
    'ollama': 'src.llm.ollama_llm.OllamaLLM',
}


def get_llm(provider: str, **kwargs) -> 'BaseLLM':
    """Return an LLM instance for *provider*.

    Parameters
    ----------
    provider:
        One of ``'gpt'``, ``'gemini'``, ``'lmstudio'``, ``'ollama'``.
    **kwargs:
        Provider-specific keyword arguments forwarded to the constructor.

    Raises
    ------
    ValueError
        If *provider* is not recognised.
    ImportError
        If the required third-party package for the provider is missing.
    """
    provider_lower = provider.lower()
    if provider_lower not in _PROVIDERS:
        available = ', '.join(sorted(_PROVIDERS))
        raise ValueError(
            f"Unknown LLM provider '{provider}'. Available: {available}"
        )

    module_path, class_name = _PROVIDERS[provider_lower].rsplit('.', 1)
    import importlib
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls(**kwargs)


__all__ = ['get_llm']
