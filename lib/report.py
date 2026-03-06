""" lib/report.py - ADScan HTML Report Generator
Generates a self-contained HTML dashboard with:
  - Light/Dark mode toggle
  - Security score gauge
  - LEFT SIDEBAR: category navigation (alphabetical, collapsible, ordered by severity)
  - Clickable, multi-select severity filter chips
  - Per-finding cards with severity badges
  - Scan metadata table
"""
from datetime import datetime
import html as html_mod

# ---------------------------------------------------------------------------
# Severity colour mapping
# ---------------------------------------------------------------------------
SEVERITY_COLORS = {
    "critical": ("#dc2626", "#fef2f2", "#7f1d1d"),
    "high":     ("#ea580c", "#fff7ed", "#7c2d12"),
    "medium":   ("#d97706", "#fffbeb", "#78350f"),
    "low":      ("#2563eb", "#eff6ff", "#1e3a8a"),
    "info":     ("#6b7280", "#f9fafb", "#374151"),
}

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK  = {s: i for i, s in enumerate(SEV_ORDER)}


def _score_color(score):
    if score >= 90: return "#16a34a"
    if score >= 75: return "#84cc16"
    if score >= 60: return "#eab308"
    if score >= 40: return "#f97316"
    return "#dc2626"

def _grade(score):
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

def _severity_badge_html(severity):
    sev = severity.lower()
    bg_light, _, _ = SEVERITY_COLORS.get(sev, ("#6b7280", "#f9fafb", "#374151"))
    return (
        f'<span class="badge badge-{sev}" '
        f'style="background:{bg_light};color:#fff;'
        f'padding:2px 10px;border-radius:12px;font-size:0.78rem;'
        f'font-weight:600;letter-spacing:0.05em;text-transform:uppercase;">'
        f'{html_mod.escape(severity.upper())}</span>'
    )

def _finding_card(finding, idx):
    severity = finding.get("severity", "info").lower()
    sev_colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    accent = sev_colors[0]
    category = finding.get("category", "Uncategorized")
    if isinstance(category, str):
        cat_list = [category]
    else:
        cat_list = list(category)
    details_html = ""
    if finding.get("details"):
        items = "".join(
            f"<li style='margin:2px 0;font-family:monospace;font-size:0.85rem;'>"
            f"{html_mod.escape(str(d)).replace('[[REDACTED]]', '<span style=\"color:#e53e3e;font-weight:bold\">REDACTED</span>')}</li>"
            for d in finding["details"][:50]
        )
        more = ""
        if len(finding["details"]) > 50:
            more = f"<li><em>... and {len(finding['details']) - 50} more</em></li>"
        details_html = f"""
        <details style='margin-top:12px;'>
          <summary style='cursor:pointer;font-weight:600;color:{accent};'>
            Affected Objects ({len(finding['details'])})
          </summary>
          <ul style='margin:8px 0 0 16px;padding:0;'>{items}{more}</ul>
        </details>"""
    cat_slug = cat_list[0].lower().replace(" ", "-").replace("&", "and").replace("/", "-")
    return f"""
    <div class="finding-card" id="finding-{idx}"
         data-severity="{severity}"
         data-category="{" ".join(c.lower().replace(" ", "-").replace("&", "and").replace("/", "-") for c in cat_list)}"
         style="border-left:4px solid {accent};background:var(--card-bg);
                padding:20px 24px;margin-bottom:16px;border-radius:8px;
                box-shadow:var(--card-shadow);">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
        <div>
          <h3 style="margin:0 0 6px;font-size:1.05rem;">{html_mod.escape(finding.get('title',''))}</h3>
          {_severity_badge_html(severity)}
          <span style="margin-left:8px;font-size:0.85rem;color:var(--text-muted);">
            Risk Deduction: <strong style="color:{accent};">-{finding.get('deduction', 0)} pts</strong>
          </span>
          <span style="margin-left:8px;font-size:0.78rem;color:var(--text-muted);
                       background:var(--rec-bg);border-radius:10px;padding:2px 8px;">
            {html_mod.escape(", ".join(cat_list))}
          </span>
        </div>
      </div>
      <p style="margin:14px 0 8px;line-height:1.6;color:var(--text-secondary);">
        {html_mod.escape(finding.get('description', ''))}
      </p>
      <div style="background:var(--rec-bg);border-radius:6px;padding:10px 14px;margin-top:8px;">
        <strong style="font-size:0.85rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">
          Recommendation
        </strong>
        <p style="margin:4px 0 0;font-size:0.92rem;line-height:1.5;">
          {html_mod.escape(finding.get('recommendation', 'Review and remediate this finding.'))}
        </p>
      </div>
      {details_html}
    </div>"""

def generate_report(output_file, domain, dc_host, username, protocols, findings, score):
    """Generate a self-contained HTML report dashboard with sidebar navigation."""
    from collections import defaultdict

    scan_time   = __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    score_color = _score_color(score)
    grade       = _grade(score)

    radius        = 80
    circumference = 2 * 3.14159 * radius
    dash_offset   = circumference * (1 - score / 100)

    # Severity counts
    sev_counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Sort findings: critical -> high -> medium -> low -> info
    findings = sorted(
        findings,
        key=lambda f: (
            _SEV_RANK.get(f.get("severity", "info").lower(), 99),
            -f.get("deduction", 0),
        ),
    )

    # ---- Sidebar ----
    cat_findings = defaultdict(list)
    for i, f in enumerate(findings):
        cats = f.get("category", "Uncategorized")
        if isinstance(cats, str):
            cats = [cats]
        for cat in cats:
            cat_findings[cat].append((i, f))

    sidebar_items_html = ""
    for cat in sorted(cat_findings.keys()):
        cat_id = cat.lower().replace(" ", "-").replace("&", "").replace("/", "-").replace(".", "")
        item_links = ""
        for idx, f in cat_findings[cat]:
            sev = f.get("severity", "info").lower()
            sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])[0]
            title_escaped = html_mod.escape(f.get("title", ""))
            item_links += (
                f'<a href="#finding-{idx}" class="sidebar-item" data-severity="{sev}"'
                f' onclick="sidebarNav(this,event)" title="{title_escaped}">'
                f'<span class="sev-dot" style="background:{sev_color};"></span>'
                f'<span class="sidebar-item-text">{title_escaped}</span>'
                f'</a>\n'
            )
        count = len(cat_findings[cat])
        sidebar_items_html += (
            f'<div class="cat-group" id="cat-{cat_id}">'
            f'<button class="cat-toggle" onclick="toggleCat(this)" aria-expanded="false">'
            f'<span class="cat-arrow">&#9660;</span>'
            f'<span class="cat-name">{html_mod.escape(cat)}</span>'
            f'<span class="cat-count">{count}</span>'
            f'</button>'
            f'<div class="cat-items collapsed">{item_links}</div>'
            f'</div>\n'
        )
    if not sidebar_items_html:
        sidebar_items_html = '<p class="sidebar-empty">No findings to navigate.</p>'

    # ---- Finding cards ----
    if findings:
        cards_html = "".join(_finding_card(f, i) for i, f in enumerate(findings))
    else:
        cards_html = (
            '<div style="text-align:center;padding:60px;color:var(--text-muted);">'
            '<div style="font-size:3rem;margin-bottom:16px;">&#10003;</div>'
            '<h3>No Vulnerabilities Found</h3>'
            '<p>All checks passed successfully.</p>'
            '</div>'
        )

    # ---- Severity chips ----
    severity_chips = ""
    for sev in SEV_ORDER:
        count = sev_counts.get(sev, 0)
        if count > 0:
            color   = SEVERITY_COLORS[sev][0]
            cap_sev = sev.capitalize()
            severity_chips += (
                f'<button class="sev-chip" data-sev="{sev}" data-color="{color}"'
                f' onclick="toggleSeverityFilter(this)"'
                f' title="Filter: {cap_sev} (multi-select)">'
                f'<span class="chip-dot" style="background:{color};"></span>'
                f'<span class="chip-count">{count}</span>'
                f'<span class="chip-label">{cap_sev}</span>'
                f'</button>'
            )
    if not severity_chips:
        severity_chips = '<span style="color:var(--text-muted);">No issues found.</span>'

    # ---- Score summary ----
    if not findings:
        score_summary = "The domain passed all checks with an excellent security posture."
    else:
        score_summary = f"{len(findings)} finding(s) identified. Click a severity chip to filter."

    # ================================================================
    # CSS  (plain string — no f-string, no {{ }} escaping needed)
    # ================================================================
    css = """
      :root {
        --bg:#f8fafc; --card-bg:#ffffff;
        --card-shadow:0 1px 3px rgba(0,0,0,0.08),0 1px 2px rgba(0,0,0,0.04);
        --text-primary:#1e293b; --text-secondary:#475569; --text-muted:#94a3b8;
        --border:#e2e8f0; --header-bg:#1e293b; --header-text:#f8fafc;
        --rec-bg:#f1f5f9; --toggle-bg:#e2e8f0; --toggle-knob:#ffffff;
        --sidebar-bg:#1e293b; --sidebar-text:#cbd5e1; --sidebar-active:#3b82f6;
        --sidebar-hover:rgba(255,255,255,0.08); --sidebar-border:#334155;
        --sidebar-width:280px;
      }
      [data-theme="dark"] {
        --bg:#0f172a; --card-bg:#1e293b;
        --card-shadow:0 1px 3px rgba(0,0,0,0.4);
        --text-primary:#f1f5f9; --text-secondary:#94a3b8; --text-muted:#64748b;
        --border:#334155; --header-bg:#020617; --header-text:#f1f5f9;
        --rec-bg:#0f172a; --toggle-bg:#3b82f6; --toggle-knob:#ffffff;
        --sidebar-bg:#020617; --sidebar-text:#94a3b8; --sidebar-active:#60a5fa;
        --sidebar-hover:rgba(255,255,255,0.06); --sidebar-border:#1e293b;
      }
      *{box-sizing:border-box;margin:0;padding:0;}
      body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
           background:var(--bg);color:var(--text-primary);
           transition:background .3s,color .3s;min-height:100vh;}
      .app-shell{display:flex;min-height:100vh;}
      .sidebar{width:var(--sidebar-width);min-width:var(--sidebar-width);
               background:var(--sidebar-bg);color:var(--sidebar-text);
               position:sticky;top:0;height:100vh;overflow-y:auto;
               display:flex;flex-direction:column;
               border-right:1px solid var(--sidebar-border);
               transition:width .25s;z-index:90;}
      .sidebar.collapsed{width:0;min-width:0;overflow:hidden;}
      .main-col{flex:1;min-width:0;display:flex;flex-direction:column;}
      header{background:var(--header-bg);color:var(--header-text);
             padding:16px 24px;display:flex;justify-content:space-between;
             align-items:center;flex-wrap:wrap;gap:12px;
             position:sticky;top:0;z-index:80;box-shadow:0 2px 8px rgba(0,0,0,.3);}
      header h1{font-size:1.3rem;font-weight:700;letter-spacing:-.02em;}
      .subtitle{font-size:.82rem;opacity:.65;margin-top:2px;}
      .header-right{display:flex;align-items:center;gap:16px;}
      .sb-toggle-btn{background:none;border:1px solid rgba(255,255,255,.2);
                     color:var(--header-text);border-radius:6px;padding:6px 10px;
                     cursor:pointer;font-size:1rem;line-height:1;}
      .toggle-wrapper{display:flex;align-items:center;gap:8px;font-size:.85rem;}
      .toggle-label{color:var(--header-text);opacity:.85;}
      .toggle{position:relative;width:44px;height:24px;cursor:pointer;}
      .toggle input{opacity:0;width:0;height:0;}
      .toggle-track{position:absolute;inset:0;background:var(--toggle-bg);
                    border-radius:24px;transition:background .3s;}
      .toggle-track::after{content:'';position:absolute;width:18px;height:18px;
                           background:var(--toggle-knob);border-radius:50%;
                           top:3px;left:3px;transition:transform .3s;
                           box-shadow:0 1px 3px rgba(0,0,0,.2);}
      input:checked + .toggle-track::after{transform:translateX(20px);}
      .sidebar-header{padding:16px 16px 12px;border-bottom:1px solid var(--sidebar-border);
                      font-size:.7rem;font-weight:700;letter-spacing:.1em;
                      text-transform:uppercase;opacity:.6;}
      .sidebar-search{margin:10px 12px;position:relative;}
      ..sidebar-search input{width:100%;background:rgba(255,255,255,.07);
                             border:1px solid var(--sidebar-border);border-radius:6px;
                             padding:6px 10px;color:var(--sidebar-text);
                             font-size:.8rem;outline:none;}
      .sidebar-search input::placeholder{opacity:.4;}
      
      .sidebar-nav{flex:1;overflow-y:auto;padding:8px 0;}
      .cat-group{margin-bottom:2px;}
      .cat-toggle{width:100%;background:none;border:none;cursor:pointer;
                  display:flex;align-items:center;gap:8px;padding:8px 16px;
                  color:var(--sidebar-text);font-size:.82rem;font-weight:600;
                  text-align:left;transition:background .15s;}
      .cat-toggle:hover{background:var(--sidebar-hover);}
      .cat-arrow{font-size:.65rem;transition:transform .2s;flex-shrink:0;opacity:.7;}
      .cat-toggle[aria-expanded="false"] .cat-arrow{transform:rotate(-90deg);}
      .cat-name{flex:1;text-overflow:ellipsis;overflow:hidden;white-space:nowrap;}
      .cat-count{background:rgba(255,255,255,.12);border-radius:10px;
                 padding:1px 7px;font-size:.72rem;flex-shrink:0;}
      .cat-items{overflow:hidden;transition:max-height .25s ease;}
      .cat-items.collapsed{max-height:0;}
      .sidebar-item{display:flex;align-items:center;gap:8px;padding:6px 16px 6px 24px;
                    font-size:.78rem;color:var(--sidebar-text);text-decoration:none;
                    transition:background .12s;cursor:pointer;
                    border-left:2px solid transparent;}
      .sidebar-item:hover{background:var(--sidebar-hover);}
      .sidebar-item.active{background:rgba(59,130,246,.15);
                           border-left-color:var(--sidebar-active);color:#fff;}
      .sev-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;}
      .sidebar-item-text{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
      .sidebar-empty{padding:16px;font-size:.82rem;opacity:.5;}
      .sidebar-footer{padding:10px 16px;border-top:1px solid var(--sidebar-border);
                      font-size:.7rem;opacity:.4;}
      .container{max-width:960px;margin:0 auto;padding:28px 20px;}
      .score-section{display:flex;align-items:center;gap:36px;
                     background:var(--card-bg);border-radius:12px;
                     padding:28px 36px;margin-bottom:24px;
                     box-shadow:var(--card-shadow);flex-wrap:wrap;}
      .gauge-wrap{position:relative;width:180px;height:180px;flex-shrink:0;}
      .gauge-wrap svg{transform:rotate(-90deg);}
      .gauge-center{position:absolute;inset:0;display:flex;flex-direction:column;
                    align-items:center;justify-content:center;}
      .gauge-score{font-size:2.8rem;font-weight:800;line-height:1;}
      .gauge-label{font-size:.78rem;color:var(--text-muted);margin-top:4px;}
      .gauge-grade{font-size:1.6rem;font-weight:700;width:40px;height:40px;
                   border-radius:50%;display:flex;align-items:center;
                   justify-content:center;color:#fff;margin-top:6px;}
      .score-info h2{font-size:1.2rem;margin-bottom:12px;}
      .chips-area{display:flex;flex-wrap:wrap;gap:4px;margin-top:12px;}
      .sev-chip{display:inline-flex;align-items:center;gap:6px;
                border:2px solid transparent;border-radius:20px;
                padding:6px 14px;cursor:pointer;font-size:.9rem;
                background:var(--card-bg);color:var(--text-primary);
                transition:all .18s ease;outline:none;
                box-shadow:var(--card-shadow);}
      .sev-chip:hover{transform:translateY(-1px);
                      box-shadow:0 4px 10px rgba(0,0,0,.15);}
      .sev-chip.active{transform:translateY(-1px);}
      .chip-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}
      .chip-count{font-weight:700;}
      .chip-label{text-transform:capitalize;color:var(--text-muted);}
      .meta-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));
                 gap:12px;background:var(--card-bg);border-radius:12px;
                 padding:20px;margin-bottom:24px;box-shadow:var(--card-shadow);}
      .meta-key{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;
                color:var(--text-muted);margin-bottom:4px;}
      .meta-val{font-weight:600;font-size:.9rem;word-break:break-all;}
      .section-header{display:flex;align-items:center;justify-content:space-between;
                      margin-bottom:14px;flex-wrap:wrap;gap:8px;}
      .section-header h2{font-size:1.1rem;}
      .finding-card{transition:box-shadow .2s;}
      .finding-card:hover{box-shadow:0 4px 12px rgba(0,0,0,.12)!important;}
      .filter-hint{font-size:.82rem;color:var(--text-muted);font-style:italic;}
      .clear-btn{background:none;border:1px solid var(--border);border-radius:12px;
                 padding:3px 12px;font-size:.8rem;color:var(--text-muted);
                 cursor:pointer;display:none;}
      .clear-btn:hover{color:var(--text-primary);border-color:var(--text-primary);}
      #no-results{display:none;text-align:center;padding:40px;
                  color:var(--text-muted);font-size:.95rem;}
      footer{text-align:center;padding:20px;color:var(--text-muted);font-size:.8rem;
             border-top:1px solid var(--border);margin-top:36px;}
      @media(max-width:768px){
        .sidebar{position:fixed;left:0;top:0;height:100vh;
                 transform:translateX(-100%);transition:transform .25s;}

        .sidebar:not(.collapsed){transform:translateX(0);}
      }
    """.strip()

    # ================================================================
    # JavaScript  (plain string — no f-string, no {{ }} escaping needed)
    # ================================================================
    js = """
      // ---- Theme ----
      (function() {
        var saved = localStorage.getItem('adscan-theme');
        if (saved === 'dark') {
          document.documentElement.setAttribute('data-theme', 'dark');
          var t = document.getElementById('darkToggle');
          if (t) t.checked = true;
        }
      })();
      function toggleTheme(el) {
        var d = el.checked;
        document.documentElement.setAttribute('data-theme', d ? 'dark' : 'light');
        localStorage.setItem('adscan-theme', d ? 'dark' : 'light');
      }

      // ---- Sidebar ----
      function toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('collapsed');
      }

      // ---- Category collapse ----
      function toggleCat(btn) {
        var expanded = btn.getAttribute('aria-expanded') === 'true';
        btn.setAttribute('aria-expanded', expanded ? 'false' : 'true');
        var items = btn.nextElementSibling;
        if (expanded) {
          items.style.maxHeight = items.scrollHeight + 'px';
          items.style.overflow  = 'hidden';
          requestAnimationFrame(function() {
            requestAnimationFrame(function() { items.style.maxHeight = '0'; });
          });
          items.addEventListener('transitionend', function h() {
            items.classList.add('collapsed');
            items.style.maxHeight = '';
            items.removeEventListener('transitionend', h);
          });
        } else {
          items.classList.remove('collapsed');
          items.style.overflow  = 'hidden';
          items.style.maxHeight = items.scrollHeight + 'px';
          items.addEventListener('transitionend', function h() {
            items.style.maxHeight = 'none';
            items.style.overflow  = '';
            items.removeEventListener('transitionend', h);
          });
        }
      }

      // ---- Sidebar search ----
      function sidebarSearchFilter(val) {
        var q = val.toLowerCase().trim();
        document.querySelectorAll('.cat-group').forEach(function(grp) {
          var any = false;
          grp.querySelectorAll('.sidebar-item').forEach(function(item) {
            var match = !q || item.querySelector('.sidebar-item-text').textContent.toLowerCase().includes(q);
            item.style.display = match ? '' : 'none';
            if (match) any = true;
          });
          grp.style.display = any ? '' : 'none';
        });
      }

      // ---- Sidebar active ----
      function sidebarNav(link, e) {
        document.querySelectorAll('.sidebar-item').forEach(function(a) { a.classList.remove('active'); });
        link.classList.add('active');
      }

      // ---- Intersection observer ----
      (function() {
        var cards = document.querySelectorAll('.finding-card[id]');
        if (!cards.length) return;
        var obs = new IntersectionObserver(function(entries) {
          entries.forEach(function(entry) {
            if (!entry.isIntersecting) return;
            var id = entry.target.id;
            document.querySelectorAll('.sidebar-item').forEach(function(a) {
              var match = a.getAttribute('href') === '#' + id;
              a.classList.toggle('active', match);
              if (match) a.scrollIntoView({block:'nearest',behavior:'smooth'});
            });
          });
        }, {threshold: 0.35});
        cards.forEach(function(c) { obs.observe(c); });
      })();

      // ---- Severity chip filter ----
      var activeFilters = {};

      function toggleSeverityFilter(btn) {
        var sev   = btn.getAttribute('data-sev');
        var color = btn.getAttribute('data-color') || '#6b7280';
        if (activeFilters[sev]) {
          delete activeFilters[sev];
          btn.classList.remove('active');
          btn.style.borderColor = 'transparent';
          btn.style.color       = '';
        } else {
          activeFilters[sev]    = true;
          btn.classList.add('active');
          btn.style.borderColor = color;
          btn.style.color       = color;
        }
        applyFilters();
      }

      function applyFilters() {
        var keys     = Object.keys(activeFilters);
        var cards    = document.querySelectorAll('.finding-card');
        var clearBtn = document.getElementById('clear-btn');
        var hintEl   = document.getElementById('filter-hint');
        var countEl  = document.getElementById('visible-count');
        var noRes    = document.getElementById('no-results');
        var vis      = 0;
        if (keys.length === 0) {
          cards.forEach(function(c) { c.style.display = ''; });
          vis = cards.length;
          if (clearBtn) clearBtn.style.display = 'none';
          if (hintEl)   hintEl.textContent = '';
        } else {
          cards.forEach(function(c) {
            var match = !!activeFilters[c.getAttribute('data-severity')];
            c.style.display = match ? '' : 'none';
            if (match) vis++;
          });
          if (clearBtn) clearBtn.style.display = 'inline-block';
          if (hintEl)   hintEl.textContent = 'Showing: ' + keys.join(', ');
        }
        if (countEl) countEl.textContent = vis;
        if (noRes)   noRes.style.display = vis === 0 ? 'block' : 'none';
      }

      function clearFilters() {
        activeFilters = {};
        document.querySelectorAll('.sev-chip').forEach(function(b) {
          b.classList.remove('active');
          b.style.borderColor = 'transparent';
          b.style.color       = '';
        });
        applyFilters();
      }

    """.strip()

    # ================================================================
    # HTML  (f-string only for Python values — NO JS or CSS braces)
    # ================================================================
    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ADScan Report - {html_mod.escape(domain)}</title>
  <style>{css}</style>
</head>
<body>
<div class="app-shell">

  <aside class="sidebar" id="sidebar">
    <div class="sidebar-header">Category Navigator</div>
    <div class="sidebar-search">
      <input type="text" id="sidebarSearch" placeholder="&#128269; Filter checks..."
             oninput="sidebarSearchFilter(this.value)">
    </div>
    <nav class="sidebar-nav" id="sidebarNav">
      {sidebar_items_html}
    </nav>
    <div class="sidebar-footer">ADScan &bull; {html_mod.escape(domain)}</div>
  </aside>

  <div class="main-col">
    <header>
      <div style="display:flex;align-items:center;gap:12px;">
        <button class="sb-toggle-btn" onclick="toggleSidebar()" title="Toggle sidebar">&#9776;</button>
        <div>
          <h1>&#x1F6E1; ADScan Report</h1>
          <div class="subtitle">Active Directory Vulnerability Assessment &mdash; {html_mod.escape(domain)}</div>
        </div>
      </div>
      <div class="header-right">
        <div class="toggle-wrapper">
          <span class="toggle-label">&#9788;</span>
          <label class="toggle">
            <input type="checkbox" id="darkToggle" onchange="toggleTheme(this)">
            <span class="toggle-track"></span>
          </label>
          <span class="toggle-label">&#9790;</span>
        </div>
      </div>
    </header>

    <div class="container">
      <div class="score-section">
        <div class="gauge-wrap">
          <svg width="180" height="180" viewBox="0 0 200 200">
            <circle cx="100" cy="100" r="{radius}" fill="none" stroke="var(--border)" stroke-width="16"/>
            <circle cx="100" cy="100" r="{radius}" fill="none" stroke="{score_color}"
                    stroke-width="16"
                    stroke-dasharray="{circumference:.2f}"
                    stroke-dashoffset="{dash_offset:.2f}"
                    stroke-linecap="round"/>
          </svg>
          <div class="gauge-center">
            <div class="gauge-score" style="color:{score_color};">{score}</div>
            <div class="gauge-label">/ 100</div>
            <div class="gauge-grade" style="background:{score_color};">{grade}</div>
          </div>
        </div>
        <div class="score-info">
          <h2>Security Score</h2>
          <p style="color:var(--text-secondary);margin-bottom:14px;line-height:1.6;">{score_summary}</p>
          <div class="chips-area">{severity_chips}</div>
        </div>
      </div>

      <div class="meta-grid">
        <div><div class="meta-key">Domain</div><div class="meta-val">{html_mod.escape(domain)}</div></div>
        <div><div class="meta-key">Domain Controller</div><div class="meta-val">{html_mod.escape(dc_host)}</div></div>
        <div><div class="meta-key">Username</div><div class="meta-val">{html_mod.escape(username)}</div></div>
        <div><div class="meta-key">Protocol(s)</div><div class="meta-val">{html_mod.escape(', '.join(p.upper() for p in protocols))}</div></div>
        <div><div class="meta-key">Scan Time</div><div class="meta-val">{html_mod.escape(scan_time)}</div></div>
        <div><div class="meta-key">Total Findings</div><div class="meta-val">{len(findings)}</div></div>
      </div>

      <div class="section-header">
        <h2>Findings (<span id="visible-count">{len(findings)}</span>)</h2>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <span class="filter-hint" id="filter-hint"></span>
          <button class="clear-btn" id="clear-btn" onclick="clearFilters()">&times; Clear filter</button>
        </div>
      </div>
      <div id="no-results">No findings match the selected filter(s).
        <a href="#" onclick="clearFilters();return false;" style="color:inherit;">Clear</a>
      </div>
      {cards_html}
    </div>

    <footer>
      Generated by <strong>ADScan</strong> &mdash; {html_mod.escape(scan_time)} &mdash;
      <a href="https://github.com/BrocktonPointSolutions/ADScan"
         style="color:inherit;text-decoration:underline;" target="_blank">
        github.com/BrocktonPointSolutions/ADScan
      </a>
    </footer>
  </div>
</div>
<script>{js}</script>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write(html_content)
