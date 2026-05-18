"""
DFD SVG Renderer (v0.6) — 生成静态 SVG + data 属性，禁止内联 onclick。
事件委托由 report-template.html 的 JS 统一处理。

交互契约:
- 每个可点击元素: data-eid, data-name, data-type, data-threats, data-analysis, class="dfd-clickable"
- data-threats 和 data-analysis 为 HTML-escaped JSON
- 无 onclick 属性
"""
import json, math, html as _html

def _esc_json(obj):
    """JSON → HTML-attribute-safe string."""
    return _html.escape(json.dumps(obj, ensure_ascii=False), quote=True)

def center(eid, positions):
    p = positions[eid]; return (p[0] + p[2] // 2, p[1] + p[3] // 2)

def edge_endpoint(eid, tx, ty, positions):
    p = positions[eid]; cx, cy = p[0] + p[2] // 2, p[1] + p[3] // 2
    dx, dy = tx - cx, ty - cy; d2 = dx * dx + dy * dy
    if d2 == 0: return (cx, cy)
    hw, hh = p[2] / 2, p[3] / 2
    if not eid.startswith(('EE', 'DS')):
        t = 1.0 / math.sqrt((dx / hw) ** 2 + (dy / hh) ** 2)
        return (cx + t * dx, cy + t * dy)
    else:
        if abs(dx) * hh > abs(dy) * hw:
            sx = hw if dx > 0 else -hw; sy = dy / dx * sx if dx != 0 else 0
        else:
            sy = hh if dy > 0 else -hh; sx = dx / dy * sy if dy != 0 else 0
        return (cx + max(-hw, min(hw, sx)), cy + max(-hh, min(hh, sy)))

def font_size(name):
    l = len(name)
    if l <= 6: return 12
    elif l <= 10: return 11
    elif l <= 14: return 10
    else: return 9

def render_svg_dfd(positions, edges, boundaries, dfd_idx, elem_desc, W=1300, H=850):
    """生成完整的交互式 SVG DFD 字符串（无内联 onclick）。"""
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="100%" height="100%">',
        '<defs>',
        '  <marker id="arw" markerWidth="9" markerHeight="7" refX="9" refY="3.5" orient="auto">',
        '    <polygon points="0 0,9 3.5,0 7" fill="#868e96"/>',
        '  </marker>',
        '</defs>',
        f'<rect width="{W}" height="{H}" fill="#f8f9fa" rx="8"/>',
    ]

    # Trust boundaries
    for tb in boundaries:
        tbid, tx, ty, tw, th, clr, label = tb
        parts.append(
            f'<rect x="{tx}" y="{ty}" width="{tw}" height="{th}" fill="none" '
            f'stroke="{clr}" stroke-width="2" stroke-dasharray="8,4" rx="12"/>'
            f'<text x="{tx + 14}" y="{ty + 20}" font-size="12" fill="{clr}" font-weight="bold">{_html.escape(label)}</text>'
        )

    # Edges — clickable via event delegation
    for src, dst, label in edges:
        sc, dc = center(src, positions), center(dst, positions)
        sp = edge_endpoint(src, dc[0], dc[1], positions)
        dp = edge_endpoint(dst, sc[0], sc[1], positions)
        mx, my = (sp[0] + dp[0]) / 2, (sp[1] + dp[1]) / 2
        df_id = f'DF_{src}_{dst}'
        edge_name = f'{src}→{dst}'
        empty_arr = '[]'

        # Transparent wide click target
        parts.append(
            f'<line x1="{sp[0]:.1f}" y1="{sp[1]:.1f}" x2="{dp[0]:.1f}" y2="{dp[1]:.1f}" '
            f'stroke="transparent" stroke-width="14" id="dfd-{df_id}" '
            f'data-eid="{df_id}" data-name="{_html.escape(edge_name)}" data-type="data_flows" '
            f'data-threats="{empty_arr}" data-analysis="&#123;&#125;" '
            f'class="dfd-clickable"><title>{_html.escape(edge_name)}: {_html.escape(label)}</title></line>'
        )
        # Visible arrow
        parts.append(
            f'<line x1="{sp[0]:.1f}" y1="{sp[1]:.1f}" x2="{dp[0]:.1f}" y2="{dp[1]:.1f}" '
            f'stroke="#adb5bd" stroke-width="2" marker-end="url(#arw)" pointer-events="none"/>'
        )
        # Clickable label
        parts.append(
            f'<text x="{mx:.0f}" y="{my - 5:.0f}" font-size="9" fill="#0d6efd" text-anchor="middle" '
            f'id="dfd-{df_id}-lbl" data-eid="{df_id}" data-name="{_html.escape(edge_name)}" '
            f'data-type="data_flows" data-threats="{empty_arr}" data-analysis="&#123;&#125;" '
            f'class="dfd-clickable dfd-edge-label">{_html.escape(label)}</text>'
        )

    # Nodes
    for eid, (x, y, w, h) in positions.items():
        threats = []
        name = eid
        analysis = {}
        for cat in ['external_entities', 'processes', 'data_stores']:
            if eid in dfd_idx.get(cat, {}):
                threats = dfd_idx[cat][eid].get('threats', [])
                name = dfd_idx[cat][eid].get('name', eid)
                analysis = dfd_idx[cat][eid].get('stride_analysis', {})
                break

        n = len(threats)
        desc = elem_desc.get(eid, '')
        elem_type = 'external_entities' if eid.startswith('EE') else ('data_stores' if eid.startswith('DS') else 'processes')
        threat_json = _esc_json(threats[:10])
        analysis_json = _esc_json(analysis)
        cx, cy = x + w // 2, y + h // 2
        title_text = f'{_html.escape(name)} — {n} 威胁'

        # Data attributes string (shared)
        data_attrs = (
            f'data-eid="{eid}" data-name="{_html.escape(name)}" data-desc="{_html.escape(desc)}" '
            f'data-type="{elem_type}" data-threats="{threat_json}" data-analysis="{analysis_json}" '
            f'class="dfd-clickable"'
        )

        if eid.startswith('DS'):
            lw, lx = w - 16, x + 8
            parts.append(
                f'<line x1="{lx}" y1="{y}" x2="{lx + lw}" y2="{y}" stroke="#198754" stroke-width="2" stroke-linecap="round"/>'
                f'<line x1="{lx}" y1="{y + h}" x2="{lx + lw}" y2="{y + h}" stroke="#198754" stroke-width="2" stroke-linecap="round"/>'
                f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="transparent" id="dfd-{eid}" '
                f'{data_attrs}><title>{title_text}</title></rect>'
            )
            tx, ty = cx, cy + 4
        elif elem_type == 'external_entities':
            parts.append(
                f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="#cfe2ff" '
                f'stroke="#0d6efd" stroke-width="2" id="dfd-{eid}" '
                f'{data_attrs}><title>{title_text}</title></rect>'
            )
            tx, ty = cx, cy + 4
        else:
            parts.append(
                f'<ellipse cx="{cx}" cy="{cy}" rx="{w // 2}" ry="{h // 2}" fill="#fff3cd" '
                f'stroke="#fd7e14" stroke-width="2" id="dfd-{eid}" '
                f'{data_attrs}><title>{title_text}</title></ellipse>'
            )
            tx, ty = cx, cy + 4

        # Label
        fz = font_size(name)
        if len(name) > 12:
            mid = len(name) // 2; sp = name.rfind(' ', 0, mid + 4)
            lines = [name[:sp].strip(), name[sp:].strip()] if sp >= 0 else [name]
        else:
            lines = [name]
        for i, line in enumerate(lines):
            parts.append(
                f'<text x="{tx}" y="{ty + (i - (len(lines) - 1) / 2) * 13:.0f}" '
                f'text-anchor="middle" font-size="{fz}" font-weight="bold" fill="#495057" '
                f'pointer-events="none">{_html.escape(line)}</text>'
            )

        # Badge
        if n > 0:
            if elem_type == 'processes':
                bx, by = cx, y + 14
            else:
                bx, by = x + w - 14, y + 14
            parts.append(
                f'<circle cx="{bx}" cy="{by}" r="10" fill="#495057" pointer-events="none"/>'
                f'<text x="{bx}" y="{by + 4}" text-anchor="middle" font-size="10" fill="#fff" '
                f'font-weight="bold" pointer-events="none">{n}</text>'
            )

    parts.append('</svg>')
    return '\n'.join(parts)
