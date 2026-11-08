from sift.adapters.bandit import BanditAdapter
from sift.adapters.base import Adapter, ToolAdapter, run_tool, scrubbed_env, warn
from sift.adapters.gitleaks import GitleaksAdapter
from sift.adapters.pmd import PmdAdapter
from sift.adapters.ruff import RuffAdapter
from sift.adapters.semgrep import SemgrepAdapter

ADAPTER_CLASSES: tuple[type[ToolAdapter], ...] = (
    SemgrepAdapter,
    PmdAdapter,
    RuffAdapter,
    BanditAdapter,
    GitleaksAdapter,
)


def all_adapters() -> list[ToolAdapter]:
    return [cls() for cls in ADAPTER_CLASSES]


__all__ = [
    "ADAPTER_CLASSES",
    "Adapter",
    "BanditAdapter",
    "GitleaksAdapter",
    "PmdAdapter",
    "RuffAdapter",
    "SemgrepAdapter",
    "ToolAdapter",
    "all_adapters",
    "run_tool",
    "scrubbed_env",
    "warn",
]
