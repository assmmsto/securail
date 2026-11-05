"""The welcome banner shown when a person starts the tool in a terminal.

Shown only to people: it is written to stderr, and only when stderr is a real
terminal, so a report redirected to a file, the JSON for scripts and AI
assistants, and --describe never contain it. NO_COLOR (no-color.org) and
--no-banner are respected. A narrow window gets a compact version.
"""

import os
import shutil
import sys

# 'ANSI Shadow' style block letters, 6 rows each. Every glyph is exactly
# _BN_CELL wide so the word lines up on a grid instead of by luck.
_BN_GLYPHS = {
    "S": ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "C": [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
    "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "I": ["██╗ ", "██║ ", "██║ ", "██║ ", "██║ ", "╚═╝ "],
    "L": ["██╗     ", "██║     ", "██║     ", "██║     ", "███████╗", "╚══════╝"],
    " ": ["   "] * 6,
}
_BN_CELL = 8

# Compact 3-row letters for narrow windows; _BN_SMALL_CELL wide, so the short
# form fits a 48-column window.
_BN_SMALL = {
    "S": ["█▀▀", "▀▀█", "▀▀▀"], "E": ["█▀▀", "█▀▀", "▀▀▀"], "C": ["█▀▀", "█  ", "▀▀▀"],
    "U": ["█ █", "█ █", "▀▀▀"], "R": ["█▀▄", "█▀▄", "▀ ▀"], "A": ["█▀█", "█▀█", "▀ ▀"],
    "I": ["▀ ", "▀ ", "▀ "], "L": ["█ ", "█ ", "▀▀"], " ": ["  "] * 3,
}
_BN_SMALL_CELL = 3

# Red, top to bottom - the archive's own colour, dark to bright.
_BN_RAMP = [(140, 12, 18), (170, 18, 24), (200, 28, 32), (222, 42, 44),
            (236, 64, 60), (246, 92, 84)]
_BN_DIM = (150, 150, 150)
_BN_ACCENT = (230, 54, 52)
_BN_TITLE = "SECURAIL"
_BN_TAGLINE = "S P Y W A R E   S C A N"


def _bn_word(text, glyphs, gap, cell):
    """The word as rows of block letters. Every cell is padded to `cell`
    columns, so a narrow glyph does not pull its neighbours out of line."""
    unknown = sorted({ch for ch in text.upper() if ch not in glyphs})
    if unknown:
        raise KeyError("no banner glyph for {!r}".format("".join(unknown)))
    rows = len(glyphs[" "])
    lines = []
    for r in range(rows):
        line = "".join(glyphs[ch][r].ljust(cell) + gap for ch in text.upper())
        lines.append(line.rstrip())
    return lines


def _bn_color_on(stream):
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not (hasattr(stream, "isatty") and stream.isatty()):
        return False
    if sys.platform == "win32":
        # Turn on the console's ANSI handling (Windows 10+); if that fails,
        # print without colour rather than as escape-code noise.
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-12)            # STD_ERROR_HANDLE
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
        except (AttributeError, OSError):
            return False
    return True


def _bn_paint(text, rgb, on):
    if not on:
        return text
    return "\x1b[38;2;{};{};{}m{}\x1b[0m".format(rgb[0], rgb[1], rgb[2], text)


def render_banner(version, width=None, color=False):
    """The banner as text. Pure: no printing, no terminal queries unless width
    is None. Used by tests and by show_banner()."""
    if width is None:
        width = shutil.get_terminal_size((100, 24)).columns
    big = _bn_word(_BN_TITLE, _BN_GLYPHS, "", _BN_CELL)
    small = width < max(len(r) for r in big) + 4
    art = (_bn_word(_BN_TITLE, _BN_SMALL, " ", _BN_SMALL_CELL) if small else big)
    ramp = _BN_RAMP[1::2] if small else _BN_RAMP
    art_w = max(len(r) for r in art)
    pad = "  "
    rule = "─" * min(art_w, max(20, width - 4))
    out = [""]
    for i, row in enumerate(art):
        out.append(pad + _bn_paint(row, ramp[i % len(ramp)], color))
    out.append("")
    out.append(pad + _bn_paint(_BN_TAGLINE, _BN_ACCENT, color)
               + _bn_paint("   v{}".format(version), _BN_DIM, color))
    out.append(pad + "Checks this device for traces of known mercenary spyware")
    out.append(pad + _bn_paint("Pegasus · Predator · Graphite · Candiru · and more", _BN_DIM, color))
    promise = ("read-only  ·  the scan never goes online  ·  nothing leaves this device"
               if width >= 80 else "read-only · offline scan · nothing leaves this device")
    out.append(pad + _bn_paint(promise, _BN_DIM, color))
    out.append(pad + _bn_paint(rule, _BN_DIM, color))
    out.append(pad + _bn_paint("by ", _BN_DIM, color) + _bn_paint("archivegenocide", _BN_ACCENT, color))
    out.append("")
    return "\n".join(out)


def show_banner(version, stream=None):
    """Print the banner for a person at a terminal; do nothing otherwise."""
    stream = stream or sys.stderr
    if not (hasattr(stream, "isatty") and stream.isatty()):
        return False
    try:
        stream.write(render_banner(version, color=_bn_color_on(stream)) + "\n")
        stream.flush()
    except (OSError, UnicodeError):
        return False
    return True
