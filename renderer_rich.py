from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Optional, Dict, List, Set, Tuple, Any, Callable

from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.box import ROUNDED
from rich import box as rich_box


@dataclass(frozen=True)
class ObjRef:
    dn: str
    name: str
    sid: Optional[str]
    classes: Tuple[str, ...]
    extra: Tuple[Tuple[str, str], ...] = ()

@dataclass(frozen=True)
class AceEdge:
    source_name: str
    effect: str
    severity: str
    mask_hex: str
    rights: Tuple[str, ...]
    object_type: Optional[str] = None


def default_theme() -> Theme:
    return Theme({
        "muted": "dim #94a3b8",
        "key": "bold #7dd3fc",
        "value": "white",

        "obj.user": "bold #38bdf8",
        "obj.group": "bold #a78bfa",
        "obj.computer": "bold #60a5fa",
        "obj.ou": "bold #fbbf24",
        "obj.domain": "bold #34d399",
        "obj.container": "bold #fbbf24",
        "obj.other": "bold white",

        "eff.allow": "bold #22c55e",
        "eff.deny": "bold #ef4444",
        "eff.audit": "bold #f59e0b",
        "eff.other": "bold white",

        "sev.crit": "bold #ef4444",
        "sev.high": "bold #f59e0b",
        "sev.med":  "bold #60a5fa",
        "sev.low":  "bold #22c55e",
        "sev.info": "bold #e5e7eb",

        "pill": "bold #0f172a on #94a3b8",
        "pill2": "bold #0f172a on #60a5fa",
    })


def obj_kind(classes: Iterable[str]) -> str:
    s = set(classes)
    if "user" in s:
        return "user"
    if "group" in s:
        return "group"
    if "computer" in s:
        return "computer"
    if "organizationalunit" in s:
        return "ou"
    if "domain" in s:
        return "domain"
    if "container" in s:
        return "container"
    return "other"


def obj_label(obj: ObjRef, no_emoji: bool = False) -> Tuple[str, str, str]:
    k = obj_kind(obj.classes)
    if no_emoji:
        icons = {
            "user": "U", "group": "G", "computer": "C",
            "ou": "OU", "domain": "D", "container": "CT", "other": "*"
        }
    else:
        icons = {
            "user": "👤", "group": "👥", "computer": "💻",
            "ou": "📁", "domain": "🌐", "container": "🗂️", "other": "◆"
        }
    styles = {
        "user": "obj.user", "group": "obj.group", "computer": "obj.computer",
        "ou": "obj.ou", "domain": "obj.domain", "container": "obj.container", "other": "obj.other"
    }
    types = {
        "user": "USER", "group": "GROUP", "computer": "COMPUTER",
        "ou": "OU", "domain": "DOMAIN", "container": "CONTAINER", "other": "OBJECT"
    }
    return icons[k], types[k], styles[k]


def truncate_middle(s: str, max_len: Optional[int]) -> str:
    if max_len is None or not s or len(s) <= max_len:
        return s
    if max_len < 10:
        return s[:max_len - 3] + "..."
    keep = (max_len - 3) // 2
    return s[:keep] + "..." + s[-keep:]


def sev_style(sev: str) -> str:
    return {
        "CRIT": "sev.crit",
        "HIGH": "sev.high",
        "MED": "sev.med",
        "LOW": "sev.low",
        "INFO": "sev.info",
    }.get(sev.upper(), "sev.info")


def eff_style(eff: str) -> str:
    return {
        "ALLOW": "eff.allow",
        "DENY": "eff.deny",
        "AUDIT": "eff.audit",
    }.get(eff.upper(), "eff.other")


def make_identity_block(obj: ObjRef, dn_max: Optional[int] = None, sid_max: Optional[int] = None) -> Table:
    t = Table(box=rich_box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("k", style="key", no_wrap=True)
    t.add_column("v", style="value")

    t.add_row("Name", Text(obj.name, style="bold"))
    t.add_row("DN", Text(truncate_middle(obj.dn, dn_max), style="dim"))

    if obj.sid:
        t.add_row("SID", Text(truncate_middle(obj.sid, sid_max), style="dim"))
    else:
        t.add_row("SID", Text("(none)", style="muted"))

    if obj.classes:
        cls = ", ".join(sorted(set(obj.classes)))
        t.add_row("Class", Text(truncate_middle(cls, dn_max), style="muted"))

    for k, v in obj.extra:
        t.add_row(k, Text(truncate_middle(v, dn_max), style="muted"))

    return t


def make_acl_table(edges: List[AceEdge], rights_max_rows: int = 14, target_guid: Optional[str] = None) -> Table:
    merged_order: List[Tuple[Tuple[str, str, str, str, Optional[str]], AceEdge]] = []
    merged_rights: Dict[Tuple[str, str, str, str, Optional[str]], List[str]] = {}

    for e in edges:
        key = (e.source_name, e.effect, e.severity, e.mask_hex, e.object_type)
        if key not in merged_rights:
            merged_rights[key] = list(e.rights)
            merged_order.append((key, e))
        else:
            for r in e.rights:
                if r not in merged_rights[key]:
                    merged_rights[key].append(r)

    edges = [
        AceEdge(
            source_name=k[0],
            effect=k[1],
            severity=k[2],
            mask_hex=k[3],
            rights=tuple(merged_rights[k]),
            object_type=k[4],
        )
        for k, e in merged_order
    ]

    t = Table(box=rich_box.SIMPLE, show_header=True, padding=(0, 1))
    t.add_column("Trustee", style="muted", no_wrap=True)
    t.add_column("Eff", no_wrap=True)
    t.add_column("Sev", no_wrap=True)
    t.add_column("Mask", style="dim", no_wrap=True)
    t.add_column("Rights", style="value", overflow="fold")
    t.add_column("GUID", style="dim", no_wrap=True)

    for e in edges:
        eff_txt = Text(e.effect, style=eff_style(e.effect))
        sev_txt = Text(e.severity, style=sev_style(e.severity))

        rights_txt = Text()
        shown = list(e.rights)[:rights_max_rows]
        for i, r in enumerate(shown):
            st = sev_style(e.severity) if i < 4 else "value"
            rights_txt.append("• ", style="muted")
            rights_txt.append(r, style=st)
            if i != len(shown) - 1:
                rights_txt.append("\n")
        if len(e.rights) > rights_max_rows:
            rights_txt.append(f"\n… +{len(e.rights) - rights_max_rows} more", style="muted")

        guid_txt = target_guid or ""
        t.add_row(e.source_name, eff_txt, sev_txt, e.mask_hex, rights_txt, guid_txt)

    return t


def make_children_table(children: List[ObjRef], dn_max: Optional[int] = None, sid_max: Optional[int] = None) -> Table:
    t = Table(box=rich_box.SIMPLE, show_header=True, padding=(0, 1))
    t.add_column("Type", style="muted", no_wrap=True)
    t.add_column("Name", style="value")
    t.add_column("DN", style="dim")
    t.add_column("SID", style="dim", no_wrap=True)

    for c in children:
        _, typ, _ = obj_label(c, no_emoji=True)
        t.add_row(
            typ,
            c.name,
            truncate_middle(c.dn, dn_max),
            truncate_middle(c.sid or "(none)", sid_max),
        )
    return t


def object_panel(
    obj: ObjRef,
    edges_from_parent: Optional[List[AceEdge]] = None,
    children: Optional[List[ObjRef]] = None,
    memberships: Optional[List[ObjRef]] = None,
    no_emoji: bool = False,
) -> Panel:
    icon, typ, style = obj_label(obj, no_emoji=no_emoji)

    def get_extra(key: str) -> Optional[str]:
        for k, v in obj.extra:
            if k == key:
                return v
        return None

    main_stack = Table(box=None, show_header=False, padding=(0, 0))
    main_stack.add_column("c")

    main_stack.add_row(make_identity_block(obj))
    main_stack.add_row(Text(""))

    if edges_from_parent:
        main_stack.add_row(
            Panel(
                make_acl_table(edges_from_parent, target_guid=get_extra("objectGUID")),
                title=Text("Access (trustees)", style="muted"),
                border_style="muted",
                box=ROUNDED,
                padding=(0, 1),
                expand=False,
            )
        )
        main_stack.add_row(Text(""))

    def card_grid(objs: List[ObjRef]) -> Table:
        g = Table.grid(expand=False, padding=(0, 0))
        for o in objs:
            o_icon, o_typ, o_style = obj_label(o, no_emoji=no_emoji)
            mini = Table(box=rich_box.SIMPLE, show_header=False, padding=(0, 1))
            mini.add_column("k", style="key", no_wrap=True)
            mini.add_column("v", style="value")
            mini.add_row("Name", Text(o.name, style="bold"))
            mini.add_row("DN", Text(truncate_middle(o.dn, 62), style="dim"))
            mini.add_row("SID", Text(truncate_middle(o.sid or "(none)", 52), style="muted"))
            g.add_row(
                Panel(
                    mini,
                    title=Text(f"{o_icon} {o_typ}", style=o_style),
                    border_style=o_style,
                    box=ROUNDED,
                    padding=(0, 1),
                    expand=False,
                )
            )
        return g

    side_sections: List[Panel] = []
    if memberships is not None:
        if memberships:
            side_sections.append(
                Panel(
                    card_grid(memberships),
                    title=Text("↪ memberOf", style="muted"),
                    border_style="muted",
                    box=ROUNDED,
                    padding=(1, 1),
                    expand=False,
                )
            )

    if children is not None:
        if children:
            side_sections.append(
                Panel(
                    card_grid(children),
                    title=Text("↪ children", style="muted"),
                    border_style="muted",
                    box=ROUNDED,
                    padding=(1, 1),
                    expand=False,
                )
            )

    layout = Table.grid(padding=(0, 0))
    layout.add_column("main", ratio=3)
    layout.add_column("side", ratio=2)
    if side_sections:
        side_stack = Table.grid(padding=(1, 0))
        side_stack.add_column("sec")
        for s in side_sections:
            side_stack.add_row(s)
        layout.add_row(main_stack, side_stack)
    else:
        layout.add_row(main_stack, Text(""))

    return Panel(layout, title=Text(f"{icon}  {typ}", style=style), border_style=style, box=ROUNDED, padding=(1, 2), expand=False)


@dataclass
class RenderLimits:
    max_depth: int = 4
    max_targets_per_trustee: Optional[int] = 30
    max_children_show: Optional[int] = 80
    max_child_trustees_expand: Optional[int] = 40


def render_acl_tree(
    console: Console,
    root: ObjRef,
    *,
    get_edges_for_trustee,
    get_children_of_dn,
    get_memberships_of_dn,
    limits: RenderLimits = RenderLimits(),
    no_emoji: bool = False,
    should_expand_trustee: Callable[[ObjRef], bool] = lambda _: True,
) -> None:
    """
    - Siempre muestra hijos de CADA objeto (si existen) usando get_children_of_dn().
    - Si un hijo tiene SID, se trata como trustee y se expanden sus edges.
    - Evita loops con visited_sid y visited_dn (control global).
    """
    def limited_children(dn: str) -> Tuple[List[ObjRef], int]:
        all_children = get_children_of_dn(dn) or []
        if limits.max_children_show is None:
            return all_children, len(all_children)
        return all_children[: limits.max_children_show], len(all_children)

    root_children, root_children_total = limited_children(root.dn)
    tree = Tree(
        object_panel(root, children=root_children, memberships=get_memberships_of_dn(root.dn), no_emoji=no_emoji),
        guide_style="bright_black",
    )
    if limits.max_children_show is not None and root_children_total > len(root_children):
        tree.add(Text(f"… showing {len(root_children)}/{root_children_total} children (cap)", style="muted"))

    visited_sid: Set[str] = set()

    if root.sid:
        visited_sid.add(root.sid)

    def rec_trustee(trustee_obj: ObjRef, node: Tree, depth: int):
        if depth >= limits.max_depth:
            node.add(Text(f"… max-depth reached ({limits.max_depth})", style="muted"))
            return
        if not should_expand_trustee(trustee_obj):
            node.add(Text("(not expanded by policy)", style="muted"))
            return
        if not trustee_obj.sid:
            node.add(Text("(no SID, cannot expand as trustee)", style="muted"))
            return

        groups = get_edges_for_trustee(trustee_obj.sid)
        if not groups:
            node.add(Text("(no outgoing ACL edges)", style="muted"))

        if limits.max_targets_per_trustee is not None and len(groups) > limits.max_targets_per_trustee:
            node.add(Text(f"… showing {limits.max_targets_per_trustee}/{len(groups)} targets (cap)", style="muted"))
            groups = groups[:limits.max_targets_per_trustee]

        for target_obj, edges in groups:
            target_children, total_children = limited_children(target_obj.dn)
            child_node = node.add(
                object_panel(
                    target_obj,
                    edges_from_parent=edges,
                    children=target_children,
                    memberships=get_memberships_of_dn(target_obj.dn),
                    no_emoji=no_emoji,
                )
            )
            if limits.max_children_show is not None and total_children > len(target_children):
                child_node.add(Text(f"… showing {len(target_children)}/{total_children} children (cap)", style="muted"))

            if target_obj.sid:
                if target_obj.sid in visited_sid:
                    child_node.add(Text("↩ already expanded elsewhere", style="muted"))
                elif should_expand_trustee(target_obj):
                    visited_sid.add(target_obj.sid)
                    rec_trustee(target_obj, child_node, depth + 1)
                else:
                    child_node.add(Text("(not expanded by policy)", style="muted"))

            if target_children:
                expanded = 0
                for ch in target_children:
                    ch_children, total_ch_children = limited_children(ch.dn)
                    ch_node = child_node.add(
                        object_panel(
                            ch,
                            children=ch_children,
                            memberships=get_memberships_of_dn(ch.dn),
                            no_emoji=no_emoji,
                        )
                    )
                    if limits.max_children_show is not None and total_ch_children > len(ch_children):
                        ch_node.add(Text(f"… showing {len(ch_children)}/{total_ch_children} children (cap)", style="muted"))

                    if not ch.sid:
                        continue
                    if ch.sid in visited_sid:
                        ch_node.add(Text("↩ already expanded elsewhere", style="muted"))
                        continue
                    if not should_expand_trustee(ch):
                        ch_node.add(Text("(not expanded by policy)", style="muted"))
                        continue
                    expanded += 1
                    if limits.max_child_trustees_expand is not None and expanded > limits.max_child_trustees_expand:
                        child_node.add(Text(f"… child trustee expansion capped at {limits.max_child_trustees_expand}", style="muted"))
                        break
                    visited_sid.add(ch.sid)
                    rec_trustee(ch, ch_node, depth + 1)

    if root.sid:
        rec_trustee(root, tree, 0)

    console.print(tree)
