"""Two-stage dedupe.

1. Fingerprint dedupe: findings with the same fingerprint (same rule family, path and
   normalized code line) on the same line merge into one Finding; `tools_agreeing` is the
   union. The same code repeated on another line is another occurrence with its own id.
2. Clustering: findings in the same file and rule family whose line ranges overlap
   form one cluster. Every member gets the cluster id and the cluster's tools_agreeing.
"""

import hashlib
from dataclasses import dataclass, field

from sift.finding import SEVERITY_RANK, Finding


@dataclass
class Cluster:
    id: str
    members: list[Finding] = field(default_factory=list)

    @property
    def representative(self) -> Finding:
        return max(
            self.members,
            key=lambda f: (SEVERITY_RANK[f.severity], len(f.tools_agreeing), -f.start_line),
        )

    @property
    def severity(self) -> str:
        return self.representative.severity

    @property
    def tools(self) -> list[str]:
        return sorted({t for f in self.members for t in f.tools_agreeing})

    @property
    def path(self) -> str:
        return self.members[0].path

    @property
    def start_line(self) -> int:
        return min(f.start_line for f in self.members)

    @property
    def end_line(self) -> int:
        return max(f.end_line for f in self.members)

    @property
    def cwe(self) -> str | None:
        return next((f.cwe for f in self.members if f.cwe), None)

    @property
    def is_secret(self) -> bool:
        return any(f.category == "secret" for f in self.members)

    def priority(self) -> int:
        """Packet ordering: severity rank x number of agreeing tools."""
        return SEVERITY_RANK[self.severity] * len(self.tools)


def dedupe(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple[str, int], Finding] = {}
    for f in findings:
        key = (f.id, f.start_line)
        existing = merged.get(key)
        if existing is None:
            merged[key] = f.model_copy(update={"tools_agreeing": sorted(set(f.tools_agreeing or [f.tool]))})
            continue
        tools = sorted(set(existing.tools_agreeing) | set(f.tools_agreeing or [f.tool]))
        keep = f if SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity] else existing
        merged[key] = keep.model_copy(
            update={
                "tools_agreeing": tools,
                "end_line": max(existing.end_line, f.end_line),
                "in_diff": existing.in_diff or f.in_diff,
                "cwe": keep.cwe or existing.cwe or f.cwe,
            }
        )
    occurrences: dict[str, int] = {}
    for f in sorted(merged.values(), key=lambda x: x.start_line):
        n = occurrences.get(f.id, 0)
        occurrences[f.id] = n + 1
        if n:  # a later identical line: distinct and order-stable, so a baseline can count them
            f.id = hashlib.sha256(f"{f.id}\x1f{n}".encode()).hexdigest()
    return list(merged.values())


def _cluster_id(members: list[Finding]) -> str:
    digest = hashlib.sha256("\n".join(sorted(f.id for f in members)).encode()).hexdigest()
    return f"C-{digest[:10]}"


def cluster(findings: list[Finding]) -> list[Cluster]:
    """Group deduped findings; returns clusters and sets cluster_id/tools_agreeing in place."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.path, f.rule_family), []).append(f)

    clusters: list[Cluster] = []
    for members in groups.values():
        members.sort(key=lambda f: (f.start_line, f.end_line, f.id))
        current: list[Finding] = []
        current_end = -1
        for f in members:
            if current and f.start_line <= current_end:
                current.append(f)
                current_end = max(current_end, f.end_line)
            else:
                if current:
                    clusters.append(Cluster("", current))
                current, current_end = [f], f.end_line
        if current:
            clusters.append(Cluster("", current))

    for c in clusters:
        c.id = _cluster_id(c.members)
        tools = c.tools
        for f in c.members:
            f.cluster_id = c.id
            f.tools_agreeing = tools
    clusters.sort(key=lambda c: (-c.priority(), c.path, c.start_line))
    return clusters
