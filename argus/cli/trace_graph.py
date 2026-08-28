from __future__ import annotations

"""ASCII investigation graph: rounded boxes, vertical flow, viewport compression."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple
from uuid import uuid4


@dataclass
class GraphNode:
    nid: str
    title: str
    subtitle: str = ""
    detail: str = ""
    children: List["GraphNode"] = field(default_factory=list)
    active: bool = False
    branch: bool = False


@dataclass
class GraphEntry:
    node: GraphNode
    branches: List[GraphNode] = field(default_factory=list)


def _strip_rich(s: str) -> str:
    for tag in ("[green]", "[/green]", "[red]", "[/red]", "[dim]", "[/dim]"):
        s = s.replace(tag, "")
    return s.replace("✓", "ok").replace("✗", "x").strip()


def _box(title: str, subtitle: str = "", detail: str = "", *, mini: bool = False) -> Tuple[List[str], int]:
    title = (title or "?")[:18]
    subtitle = (subtitle or "")[:20]
    detail = _strip_rich(detail)[:22]
    if mini:
        line = f"{title} · {subtitle}"[:24] or title
        if detail:
            line = f"{title} · {detail}"[:24]
        inner_w = min(max(len(line), 8), 24)
        lines = [
            "╭" + "─" * inner_w + "╮",
            "│" + line.center(inner_w) + "│",
            "╰" + "─" * inner_w + "╯",
        ]
        return lines, inner_w + 2
    inner_w = min(max(len(title), len(subtitle), len(detail), 6), 20)
    lines = [
        "╭" + "─" * inner_w + "╮",
        "│" + title.center(inner_w) + "│",
    ]
    if subtitle:
        lines.append("│" + subtitle.center(inner_w) + "│")
    if detail:
        lines.append("│" + detail.center(inner_w) + "│")
    lines.append("╰" + "─" * inner_w + "╯")
    return lines, inner_w + 2


def _arrow(width: int = 8) -> List[str]:
    x = max(0, width // 2)
    return [" " * x + "│", " " * x + "▼"]


def _center_graph_lines(lines: List[str]) -> List[str]:
    """Center each row on the widest line so arrows sit under boxes."""
    if not lines:
        return lines
    width = max(len(line) for line in lines)
    return [line.center(width) for line in lines]


def _pad_graph_canvas(lines: List[str], canvas_width: int) -> List[str]:
    if not lines or canvas_width <= 0:
        return lines
    return [line.center(canvas_width) for line in lines]


@dataclass
class InvestigationGraph:
    root: GraphNode = field(default_factory=lambda: GraphNode("start", "START", subtitle="agent"))
    _tip: GraphNode = field(init=False)
    _modules: Dict[str, GraphNode] = field(default_factory=dict)
    _entries: List[GraphEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._tip = self.root

    def _id(self) -> str:
        return uuid4().hex[:6]

    def _set_active(self, node: GraphNode) -> None:
        stack = [self.root]
        while stack:
            n = stack.pop()
            n.active = n is node
            for c in n.children:
                stack.append(c)

    def add(
        self,
        title: str,
        subtitle: str = "",
        detail: str = "",
        *,
        module: str = "",
        fan_out: Optional[List[str]] = None,
    ) -> GraphNode:
        parent = self._modules.get(module) if module else self._tip
        if parent is None:
            parent = self._tip
        node = GraphNode(self._id(), title, subtitle=subtitle, detail=detail)
        parent.children.append(node)
        self._tip = node
        self._set_active(node)

        branches: List[GraphNode] = []
        if fan_out:
            for name in fan_out[:4]:
                leaf = GraphNode(self._id(), name[:18], subtitle="file", branch=True)
                node.children.append(leaf)
                self._modules[name] = leaf
                branches.append(leaf)

        self._entries.append(GraphEntry(node=node, branches=branches))
        return node

    def render(self, max_lines: int = 28, canvas_width: int = 0) -> str:
        max_lines = max(10, max_lines)
        full = self._render_all(mini_tail=False)
        if len(full) <= max_lines:
            lines = _center_graph_lines(full)
            return "\n".join(lines)

        # Keep START tiny + compress middle + show recent tail
        tail_count = max(3, min(5, (max_lines - 8) // 6))
        hidden = self._entries[:-tail_count] if len(self._entries) > tail_count else []
        tail = self._entries[-tail_count:]

        parts: List[str] = []
        parts.extend(_box("START", "agent", mini=True)[0])
        parts.extend(_arrow(10))

        if hidden:
            parts.extend(self._compress_banner(len(hidden), hidden))
            parts.extend(_arrow(10))

        parts.extend(self._render_entries(tail, mini=(len(tail) > 3)))
        # If still too tall, mini-mode for all but active
        while len(parts) > max_lines and tail_count > 2:
            tail_count -= 1
            hidden = self._entries[:-tail_count]
            tail = self._entries[-tail_count:]
            parts = []
            parts.extend(_box("START", "agent", mini=True)[0])
            parts.extend(_arrow(10))
            if hidden:
                parts.extend(self._compress_banner(len(hidden), hidden))
                parts.extend(_arrow(10))
            parts.extend(self._render_entries(tail, mini=True))

        lines = _center_graph_lines(parts[:max_lines])
        return "\n".join(lines)

    def _render_all(self, *, mini_tail: bool) -> List[str]:
        parts: List[str] = []
        parts.extend(_box("START", self.root.subtitle)[0])
        parts.extend(_arrow(10))
        parts.extend(self._render_entries(self._entries, mini=mini_tail))
        return parts

    def _compress_banner(self, count: int, entries: Sequence[GraphEntry]) -> List[str]:
        labels = [e.node.title for e in entries[-6:]]
        chain = " → ".join(labels)
        if len(entries) > 6:
            chain = " → ".join(e.node.title for e in entries[:3]) + " → … → " + " → ".join(labels[-2:])
        text = f"… {count} steps · {chain}"
        if len(text) > 38:
            text = f"… {count} steps · " + " → ".join(e.node.title for e in entries[:2]) + " → …"
        inner = min(max(len(text), 12), 40)
        return [
            "╭" + "─" * inner + "╮",
            "│" + text[:inner].center(inner) + "│",
            "╰" + "─" * inner + "╯",
        ]

    def _render_entries(self, entries: Sequence[GraphEntry], *, mini: bool) -> List[str]:
        out: List[str] = []
        for i, entry in enumerate(entries):
            n = entry.node
            label = ("▸ " + n.title) if n.active else n.title
            use_mini = mini and not n.active
            box, w = _box(label, n.subtitle, n.detail, mini=use_mini)
            if i:
                out.extend(_arrow(w))
            out.extend(box)
            if entry.branches and not use_mini:
                out.extend(_arrow(w))
                out.extend(self._fan_lines(entry.branches))
        return out

    def _fan_lines(self, branches: List[GraphNode]) -> List[str]:
        if not branches:
            return []
        if len(branches) == 1:
            return _box(branches[0].title, branches[0].subtitle, mini=True)[0]

        boxes = [_box(b.title, b.subtitle, mini=True)[0] for b in branches]
        widths = [len(b[0]) for b in boxes]
        gap = 1
        total = sum(widths) + gap * (len(widths) - 1)

        centers: List[int] = []
        x = 0
        for w in widths:
            centers.append(x + w // 2)
            x += w + gap

        rail = ["─"] * total
        for c in centers:
            if 0 <= c < total:
                rail[c] = "▼"
        if len(centers) >= 2:
            for k in range(centers[0], centers[-1] + 1):
                if 0 <= k < total and rail[k] == " ":
                    rail[k] = "─"
            rail[centers[0]] = "┌" if rail[centers[0]] == "─" else rail[centers[0]]
            rail[centers[-1]] = "┐" if rail[centers[-1]] == "─" else rail[centers[-1]]

        out: List[str] = ["".join(rail)]
        h = max(len(b) for b in boxes)
        for row in range(h):
            parts: List[str] = []
            for bi, b in enumerate(boxes):
                parts.append(b[row] if row < len(b) else " " * widths[bi])
                if bi < len(boxes) - 1:
                    parts.append(" " * gap)
            out.append("".join(parts))
        return out
