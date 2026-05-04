"""
lib/tools.py — External CLI Tool Manager (uv-based isolation)

Manages external CLI tools (certipy-ad, netexec/nxc, etc.) that ADScan
invokes via subprocess.  Each tool is installed into its own isolated
virtual environment using ``uv tool install``, preventing dependency
conflicts with ADScan's own packages.

Usage from a check module::

    from lib.tools import ensure_tool

    exe = ensure_tool("certipy")      # returns absolute path or None
    if exe is None:
        return [_info_finding("certipy-ad not available")]
    subprocess.run([exe, "find", ...])

Pre-install all registered tools at once (used by ``--setup-tools``)::

    from lib.tools import setup_all_tools
    results = setup_all_tools()       # {"certipy": "/path/...", "nxc": None}
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess  # nosec B404 — required to invoke uv
from dataclasses import dataclass

_log = logging.getLogger("adscan")


# ---------------------------------------------------------------------------
# Tool specification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolSpec:
    """Immutable descriptor for an external CLI tool."""

    package: str                    # PyPI package name (e.g. "certipy-ad")
    exe: str                        # Primary executable name (e.g. "certipy")
    description: str                # Human-readable purpose
    version: str | None = None      # Optional version pin (e.g. "4.8.2")
    fallback_exe: str | None = None # Legacy exe name to check before installing

    @property
    def pip_spec(self) -> str:
        """Return the pip/uv install specifier, e.g. ``certipy-ad==4.8.2``."""
        return f"{self.package}=={self.version}" if self.version else self.package


# ---------------------------------------------------------------------------
# Registry — add new tools here
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, ToolSpec] = {
    "certipy": ToolSpec(
        package="certipy-ad",
        exe="certipy",
        description="ADCS / PKI vulnerability scanner (v5.x requires Python 3.12+)",
        fallback_exe="certipy-ad",  # Kali / older certipy versions
    ),
    "nxc": ToolSpec(
        package="netexec",
        exe="nxc",
        description="Network enumeration tool (SMB signing, SMBv1)",
    ),
    "bloodhound": ToolSpec(
        package="bloodhound",
        exe="bloodhound-python",
        description="Legacy BloodHound AD ingestor — collects graph data for attack path analysis",
    ),
    "bloodhound-ce": ToolSpec(
        package="bloodhound-ce",
        exe="bloodhound-ce-python",
        description="BloodHound Community Edition AD ingestor",
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ensure_tool(slug: str) -> str | None:
    """Return the absolute path to a tool's executable, installing it if needed.

    Lookup order:
      1. Primary exe on ``PATH`` → return immediately (zero-cost hot path).
      2. Fallback exe on ``PATH`` (e.g. ``certipy-ad`` for older installs).
      3. ``uv tool install <spec>`` → install into an isolated venv, then
         re-check ``PATH``.
      4. ``uv`` not available → log a warning with manual install instructions
         and return ``None``.

    Parameters
    ----------
    slug:
        Key into :data:`TOOL_REGISTRY` (e.g. ``"certipy"``, ``"nxc"``).

    Returns
    -------
    str | None
        Absolute path to the executable, or ``None`` if the tool could not
        be found or installed.
    """
    spec = TOOL_REGISTRY.get(slug)
    if spec is None:
        _log.warning("  [tools] Unknown tool slug: %s", slug)
        return None

    # Fast path — already on PATH (check primary and fallback exe names)
    path = shutil.which(spec.exe)
    if path is not None:
        return path
    if spec.fallback_exe:
        path = shutil.which(spec.fallback_exe)
        if path is not None:
            return path

    # Attempt auto-install via uv
    uv = shutil.which("uv")
    if uv is None:
        _log.warning(
            "  [tools] %s not found and uv is not installed.\n"
            "          Install uv:  curl -LsSf https://astral.sh/uv/install.sh | sh\n"
            "          Then run:    uv tool install %s\n"
            "          Or install directly:  pip install %s",
            spec.exe, spec.pip_spec, spec.pip_spec,
        )
        return None

    return _uv_tool_install(uv, spec)


def setup_all_tools() -> dict[str, str | None]:
    """Install every registered tool and return a slug → path mapping.

    Used by the ``--setup-tools`` CLI flag for one-shot provisioning.
    Bootstraps ``uv`` itself first when it is not already on ``PATH``,
    so a freshly-pipx-installed ADScan can install everything with a
    single ``adscan --setup-tools`` invocation.
    """
    _bootstrap_uv()
    return {slug: ensure_tool(slug) for slug in TOOL_REGISTRY}


def _bootstrap_uv() -> str | None:
    """Return the path to ``uv``, running Astral's official installer when
    it is missing.

    The installer drops ``uv`` into ``~/.local/bin`` (or ``~/.cargo/bin``
    on some systems); both are added to ``PATH`` for the current process
    so subsequent ``shutil.which("uv")`` calls succeed without the user
    having to re-source their shell rc file.
    """
    path = shutil.which("uv")
    if path:
        return path

    _log.info("  [tools] uv is not on PATH — running the official installer")
    _log.info("  [tools] (curl -LsSf https://astral.sh/uv/install.sh | sh)")
    try:
        result = subprocess.run(
            ["sh", "-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"],
            text=True,
            timeout=300,
        )  # nosec B602 — single fixed Astral URL, no user input
    except FileNotFoundError:
        _log.warning(
            "  [tools] sh or curl is not available; install uv manually:\n"
            "          curl -LsSf https://astral.sh/uv/install.sh | sh"
        )
        return None
    except Exception as exc:
        _log.warning("  [tools] uv installer failed to launch: %s", exc)
        return None

    if result.returncode != 0:
        _log.warning(
            "  [tools] uv installer exited rc=%d — install uv manually",
            result.returncode,
        )
        return None

    # The installer puts uv in ~/.local/bin or ~/.cargo/bin; add both so the
    # current process picks it up without sourcing a shell rc file.
    for extra in (
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/.cargo/bin"),
    ):
        current = os.environ.get("PATH", "")
        if extra and extra not in current.split(os.pathsep):
            os.environ["PATH"] = extra + os.pathsep + current

    path = shutil.which("uv")
    if path:
        _log.info("  [tools] uv installed -> %s", path)
    else:
        _log.warning(
            "  [tools] uv installer ran but the binary is not on PATH; "
            "add ~/.local/bin to your shell PATH and re-run --setup-tools",
        )
    return path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _uv_tool_install(uv: str, spec: ToolSpec) -> str | None:
    """Run ``uv tool install <spec>`` and return the exe path or None."""
    _log.info("  [tools] Installing %s via uv tool install ...", spec.pip_spec)
    try:
        result = subprocess.run(
            [uv, "tool", "install", spec.pip_spec],
            capture_output=True,
            text=True,
            timeout=120,
        )  # nosec B603 — command is a validated list, no shell interpolation
        if result.returncode == 0:
            path = shutil.which(spec.exe) or (
                shutil.which(spec.fallback_exe) if spec.fallback_exe else None
            )
            if path is not None:
                _log.info("  [tools] Installed %s -> %s", spec.pip_spec, path)
                return path
            _log.warning(
                "  [tools] uv tool install succeeded but %s not found on PATH. "
                "Ensure ~/.local/bin is in your PATH.",
                spec.exe,
            )
        else:
            stderr = result.stderr.strip()
            _log.warning(
                "  [tools] uv tool install %s failed (rc=%d): %s",
                spec.pip_spec, result.returncode, stderr,
            )
    except subprocess.TimeoutExpired:
        _log.warning(
            "  [tools] uv tool install %s timed out after 120s", spec.pip_spec,
        )
    except Exception as exc:
        _log.warning("  [tools] uv tool install %s error: %s", spec.pip_spec, exc)
    return None
