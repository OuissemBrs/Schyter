"""Interactive controls for the matplotlib sequence animation (Play/Pause, step, restart).

Used by ``protoverify animate --engine mpl --show``.  The widgets are created on
the same figure the :class:`~matplotlib.animation.FuncAnimation` draws into, so
the user can pause, walk the trace one frame at a time and scrub with the slider.
"""

from __future__ import annotations

from collections.abc import Callable

from .common import Renderer, RenderOptions

__all__ = ["StepPlayer", "attach_controls"]


class StepPlayer:
    """A tiny manual frame player driving a ``FuncAnimation``."""

    def __init__(self, animation: object, draw: Callable[[int], None], total: int) -> None:
        self.animation = animation
        self.draw = draw
        self.total = total
        self.index = 0
        self.playing = True

    def seek(self, index: int) -> None:
        """Jump to ``index`` and redraw."""
        self.index = max(0, min(index, self.total - 1))
        self.draw(self.index)
        figure = getattr(self.animation, "_fig", None)
        if figure is not None:
            figure.canvas.draw_idle()  # pragma: no cover - interactive only

    def step(self, delta: int) -> None:
        """Move ``delta`` frames forward (or backwards)."""
        self.pause()
        self.seek(self.index + delta)

    def pause(self) -> None:
        """Stop the automatic playback."""
        self.playing = False
        pause = getattr(self.animation, "event_source", None)
        if pause is not None:  # pragma: no cover - interactive only
            self.animation._stop()  # type: ignore[attr-defined]

    def play(self) -> None:
        """Resume the automatic playback."""
        self.playing = True

    def restart(self) -> None:
        """Jump back to the first frame and resume playing."""
        self.seek(0)
        self.play()


def attach_controls(
    figure: object,
    animation: object,
    renderer: Renderer,
    ax: object,
    panel: object,
    total: int,
    options: RenderOptions,
) -> StepPlayer:
    """Add Play/Pause, Step, Back, Restart and a frame slider to ``figure``."""
    from matplotlib.widgets import Button, Slider

    per_step = max(1, options.subframes)
    draw: Callable[[int], None] = lambda frame: renderer.draw(ax, panel, frame)  # noqa: E731
    player = StepPlayer(animation, draw, total)
    figure.subplots_adjust(bottom=0.22)  # type: ignore[attr-defined]

    play_ax = figure.add_axes([0.08, 0.09, 0.08, 0.05])  # type: ignore[attr-defined]
    prev_ax = figure.add_axes([0.18, 0.09, 0.08, 0.05])  # type: ignore[attr-defined]
    next_ax = figure.add_axes([0.28, 0.09, 0.08, 0.05])  # type: ignore[attr-defined]
    again_ax = figure.add_axes([0.38, 0.09, 0.08, 0.05])  # type: ignore[attr-defined]
    slider_ax = figure.add_axes([0.50, 0.10, 0.42, 0.03])  # type: ignore[attr-defined]

    buttons = [
        (Button(play_ax, "Play"), lambda _e: player.play()),
        (Button(prev_ax, "< Back"), lambda _e: player.step(-per_step)),
        (Button(next_ax, "Step >"), lambda _e: player.step(per_step)),
        (Button(again_ax, "Restart"), lambda _e: player.restart()),
    ]
    slider = Slider(slider_ax, "frame", 0, max(0, total - 1), valinit=0, valstep=1)

    def on_slide(value: float) -> None:
        player.pause()
        player.seek(int(value))

    slider.on_changed(on_slide)
    for widget, handler in buttons:
        widget.on_clicked(handler)
    return player
