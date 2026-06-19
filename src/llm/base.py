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

    def analyze_flow(
        self,
        taint_flow: list[str],
        functions: list[dict],
        sink_decompiled: str,
        custom_prompt: str | None = None,
    ) -> str:
        """Build a taint-flow summary prompt and call ``chat``.

        Parameters
        ----------
        taint_flow:
            Ordered list of function addresses forming the path,
            from source to sink.
        functions:
            Full function records for each hop (name, address,
            decompiled_code, llm_result, …).
        sink_decompiled:
            Decompiled pseudo-C of the sink function.
        custom_prompt:
            If provided, used as the full prompt prefix instead of the
            built-in template.

        Returns
        -------
        str
            Raw LLM response text summarising the taint flow.
        """
        # Build a compact per-hop summary from the per-function LLM results
        hop_lines: list[str] = []
        addr_to_func = {f['address']: f for f in functions}
        for addr in taint_flow:
            rec = addr_to_func.get(addr, {})
            name = rec.get('function_name', addr)
            summary = rec.get('llm_result', '') or ''
            hop_lines.append(f'  {addr}  {name}: {summary}')
        hops_text = '\n'.join(hop_lines)

        sink_addr = taint_flow[-1] if taint_flow else ''
        source_addr = taint_flow[0] if taint_flow else ''

        base_prompt = custom_prompt or (
            'You are a binary security analyst specializing in taint analysis.\n'
            'The following taint flow was discovered in a firmware binary.\n'
            'Taint originates at the SOURCE function and reaches the SINK function '
            'via the call chain shown below.\n\n'
            f'Source: {source_addr}\n'
            f'Sink:   {sink_addr}\n\n'
            f'Call chain ({len(taint_flow)} hops):\n{hops_text}\n\n'
            'Sink function decompiled code:\n'
            f'{sink_decompiled}\n\n'
            'Please:\n'
            '1. Describe how untrusted data could flow from the source to the sink.\n'
            '2. Assess the severity of the potential vulnerability.\n'
            '3. Suggest a brief mitigation.\n\n'
            'Respond with valid JSON with keys: '
            '"flow_description" (string), "severity" (critical|high|medium|low), '
            '"mitigation" (string).\n'
        )
        return self.chat(base_prompt)

