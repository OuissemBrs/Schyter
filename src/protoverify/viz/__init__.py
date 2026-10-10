"""Animation back-ends.

Nothing in this package imports the search engine: renderers only read a
:class:`~protoverify.core.trace.Trace` produced by the verifier, which keeps the
trace JSON contract in ``docs/trace-schema.md`` the single interface.
"""

from __future__ import annotations

from .common import RenderOptions, load_trace
from .export import available_engines, render_trace

__all__ = ["RenderOptions", "available_engines", "load_trace", "render_trace"]
