"""Self-contained HTML report for Pipeline-Gate (no external assets; works offline and in CI artifacts).
Drop-in replacement for backend/reports/html_report.py.
generate_html_report(scan_id, findings, gate, risk_score, scanners_run=None) -> str
"""
from __future__ import annotations

import html
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
STAGES = [("sast", "SAST", "Semgrep"), ("sca", "SCA", "Trivy"),
          ("secrets", "Secrets", "Gitleaks"), ("dast", "DAST", "OWASP ZAP")]
TOOL_STAGE = {"semgrep": "sast", "trivy": "sca", "gitleaks": "secrets", "zap": "dast"}
ICONS = {
    "sast": '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14"/>',
    "sca": '<path d="M12 3 4 7v10l8 4 8-4V7l-8-4zM4 7l8 4 8-4M12 11v10"/>',
    "secrets": '<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8m-3 3 3 3"/>',
    "dast": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    "open": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.5-1.5"/>',
    "chk": '<path d="m5 12 5 5 9-10"/>',
}
FIXES = [
    (r"secret|api key|token|password|gitleaks", "Credentials in source can be copied by anyone with repo access.",
     "Revoke and rotate the credential, purge it from git history, and load it from an environment variable or secret manager."),
    (r"debug", "Debug mode can expose an interactive console and stack traces.",
     "Disable debug in production and control it with an environment variable."),
    (r"bad_host|0\.0\.0\.0", "Binding to all interfaces exposes the service on every network.",
     "Bind to 127.0.0.1 or place the app behind a reverse proxy."),
    (r"pickle", "Unpickling untrusted data can run arbitrary code.",
     "Use JSON or another safe format, or sign and verify the data first."),
    (r"shell", "shell=True lets crafted input inject extra commands.",
     "Pass arguments as a list and set shell=False."),
    (r"md5|sha1", "MD5 and SHA-1 are fast to brute-force and unfit for passwords.",
     "Use bcrypt, scrypt or argon2 for password hashing."),
    (r"content security policy|csp|header", "Missing security headers weaken the browser's built-in protections.",
     "Add the header in your web server or framework middleware, then re-run DAST."),
    (r"urllib3|jinja|redos|cve|crlf|injection|decompression|redirect", "A vulnerable dependency version is in use.",
     "Upgrade to the fixed version listed by Trivy and re-run the scan."),
]

def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _sev(f: Any) -> str:
    s = str(getattr(f, "severity", "INFO") or "INFO").upper()
    return s if s in SEV_RANK else "INFO"


def _key(f: Any) -> tuple:
    return (getattr(f, "tool", None), getattr(f, "rule_id", None), getattr(f, "file", None), getattr(f, "line", None))


def _path(f: Any) -> str:
    p = getattr(f, "file", None)
    if p:
        p = str(p).replace("\\", "/")
        root = Path.cwd().as_posix().rstrip("/") + "/"
        if p.lower().startswith(root.lower()):
            p = p[len(root):]
        return p
    return getattr(f, "url", None) or "(no location)"


def _loc(f: Any) -> str:
    line = getattr(f, "line", None)
    return f"{_path(f)}:{line}" if getattr(f, "file", None) and line else _path(f)


def _stage(f: Any) -> str:
    cat = str(getattr(f, "category", "") or "").lower()
    if cat in ICONS and cat in {s[0] for s in STAGES}:
        return cat
    tool = str(getattr(f, "tool", "") or "").lower()
    return next((v for k, v in TOOL_STAGE.items() if k in tool), "")


def _fix(f: Any) -> tuple[str, str]:
    text = f"{getattr(f, 'title', '')} {getattr(f, 'rule_id', '')} {getattr(f, 'tool', '')}".lower()
    for pat, why, fix in FIXES:
        if re.search(pat, text):
            return why, fix
    return "Reported by the scanner.", "Review the rule documentation, then fix it or document an exception."


def _svg(path: str) -> str:
    return (f'<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{path}</svg>')


def generate_html_report(scan_id: str, findings: list[Any], gate: Any, risk_score: float, scanners_run: list[str] | None = None) -> str:
    findings = sorted(findings, key=lambda f: SEV_RANK[_sev(f)])
    total = len(findings)
    counts = Counter(_sev(f) for f in findings)
    passed = bool(getattr(gate, "passed", False))
    reason = str(getattr(gate, "reason", "") or ("All checks passed" if passed else "Policy violations detected"))
    blocking = {_key(f) for f in (getattr(gate, "offending", None) or [])}
    ran = {str(x).lower() for x in scanners_run} if scanners_run else None
    score = float(risk_score or 0)
    cls = "pass" if passed else "fail"
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # pipeline strip
    by_stage = Counter(_stage(f) for f in findings)
    nodes = []
    for sid, name, tool in STAGES:
        if ran is not None and sid not in ran:
            state, label, icon = "skipped", "Skipped", ICONS[sid]
        else:
            n = by_stage.get(sid, 0)
            if n:
                state, label, icon = "found", f"{n} finding{'s' if n != 1 else ''}", ICONS[sid]
            else:
                state, label, icon = "clean", ("Clean" if ran is not None else "No findings"), ICONS["chk"]
        nodes.append(f'<div class="node {state}"><div class="ring">{_svg(icon)}</div><b>{name}</b><span>{tool}</span><em>{label}</em></div>')
    gate_state = "open" if passed else "locked"
    nodes.append(f'<div class="node {gate_state}"><div class="ring">{_svg(ICONS["open" if passed else "lock"])}</div>'
                 f'<b>Gate</b><span>Policy check</span><em>{"Passed" if passed else "Blocked"}</em></div>')
    pipeline = '<div class="conn"></div>'.join(nodes)

    # stats + distribution
    stats = f'<div class="stat"><div class="n">{total}</div><div class="l">Total</div></div>' + "".join(
        f'<div class="stat"><div class="n">{counts.get(s, 0)}</div><div class="l"><i class="dot s-{s}"></i>{s.title()}</div></div>'
        for s in SEVERITIES[:4])
    dist = "".join(f'<i class="s-{s}b" style="flex:{counts[s]}" title="{counts[s]} {s.title()}"></i>' for s in SEVERITIES if counts.get(s))

    # matrix
    tools = sorted({str(getattr(f, "tool", "") or "unknown") for f in findings})
    mx = '<div class="h"></div>' + "".join(f'<div class="h">{s.title()}</div>' for s in SEVERITIES)
    for t in tools:
        mx += f'<div class="rl">{_e(t)}</div>'
        for s in SEVERITIES:
            n = sum(1 for f in findings if str(getattr(f, "tool", "") or "unknown") == t and _sev(f) == s)
            mx += (f'<button data-s="{s}" data-k="{_e(t)}" class="cell s-{s}c" style="--n:{min(18 + n * 9, 70)}%" '
                   f'aria-label="{n} {s.title()} from {_e(t)}">{n}</button>') if n else '<div class="nil">·</div>'

    # hotspots
    spots = Counter(_path(f) for f in findings).most_common(5)
    peak = spots[0][1] if spots else 1
    hot = "".join(f'<div class="hs"><span class="loc">{_e(p)}</span><span class="bar"><i style="width:{n / peak * 100:.0f}%"></i></span><b>{n}</b></div>'
                  for p, n in spots) or '<div class="empty">No findings.</div>'

    # rows
    rows = []
    for f in findings:
        sv, tool, title = _sev(f), str(getattr(f, "tool", "") or "unknown"), str(getattr(f, "title", "") or getattr(f, "rule_id", ""))
        blocks = _key(f) in blocking
        why, fix = _fix(f)
        cwe = getattr(f, "cwe_id", None)
        cwe = ", ".join(map(str, cwe)) if isinstance(cwe, (list, tuple)) else cwe
        desc = getattr(f, "description", "") or ""
        extra = "".join(
            f'<div><h4>{h}</h4><p>{_e(v)}</p></div>' for h, v in
            [("Description", desc if desc and desc != title else ""), ("Why it matters", why), ("How to fix", fix)] if v)
        meta = f'<span class="sc">{_e(getattr(f, "rule_id", ""))}</span>' if getattr(f, "rule_id", None) else ""
        meta += f' <span class="sc">{_e(cwe)}</span>' if cwe else ""
        search = f"{sv} {tool} {_loc(f)} {title}".lower()
        rows.append(
            f'<tr class="r" data-s="{sv}" data-k="{_e(tool)}" data-q="{_e(search)}" tabindex="0" aria-expanded="false">'
            f'<td><span class="sev"><i class="dot s-{sv}"></i>{sv}</span></td><td><span class="sc">{_e(tool)}</span></td>'
            f'<td class="loc">{_e(_loc(f))}</td><td>{_e(title)}{" <span class=pill>Blocking</span>" if blocks else ""}</td></tr>'
            f'<tr class="d" hidden><td colspan="4"><div class="dg">{extra}<div>{meta}</div></div></td></tr>')
    chips = '<button class="chip" data-v="" aria-pressed="true">All</button>' + "".join(
        f'<button class="chip" data-v="{s}" aria-pressed="false">{s.title()} · {counts[s]}</button>' for s in SEVERITIES if counts.get(s))
    tool_opts = "".join(f"<option>{_e(t)}</option>" for t in tools)

    return (_PAGE
            .replace("__CSS__", _CSS).replace("__JS__", _JS)
            .replace("__SCAN__", _e(scan_id)).replace("__NOW__", now).replace("__CLS__", cls)
            .replace("__TITLE__", "Gate passed" if passed else "Gate failed").replace("__REASON__", _e(reason))
            .replace("__SCORE__", f"{score:.0f}").replace("__SCOREW__", f"{min(score, 100):.0f}")
            .replace("__PIPE__", pipeline).replace("__STATS__", stats).replace("__DIST__", dist)
            .replace("__MX__", mx).replace("__HOT__", hot).replace("__CHIPS__", chips)
            .replace("__TOOLS__", tool_opts).replace("__ROWS__", "".join(rows)).replace("__TOTAL__", str(total)))


_CSS = """
:root{--bg:#e9edf1;--sf:#fff;--sf2:#f5f7f9;--ink:#0e1a24;--mu:#5a6a78;--ln:#d8dfe6;--ac:#0b7a75;
--fail:#b42318;--failb:#fde8e6;--pass:#067647;--passb:#e2f4ea;--warn:#a85a00;
--crit:#7a1230;--high:#d92d20;--med:#e08a00;--low:#2877cf;--info:#8795a3;
--sans:"Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,"Cascadia Mono",Consolas,Menlo,monospace}
@media(prefers-color-scheme:dark){:root{--bg:#0a1016;--sf:#121b24;--sf2:#18232e;--ink:#e6edf3;--mu:#92a3b3;--ln:#243240;--ac:#3dd6c6;
--fail:#ff8a7e;--failb:#3a1b1e;--pass:#5fd39a;--passb:#11301f;--warn:#f5b45c;--crit:#ff7aa0;--high:#ff6b5e;--med:#f5a63d;--low:#6aa8ff;--info:#7b8b9b}}
*{box-sizing:border-box}html{color-scheme:light dark}
body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.5 var(--sans)}
:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
header{display:flex;align-items:center;gap:14px;padding:14px 28px;background:var(--sf);border-bottom:1px solid var(--ln)}
.logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:18px;letter-spacing:-.02em;margin-right:auto;color:var(--ink)}.logo svg{color:var(--ac)}
.meta{font:12px var(--mono);color:var(--mu)}
.btn{font:600 13px var(--sans);border:1px solid var(--ln);border-radius:8px;padding:7px 13px;cursor:pointer;background:transparent;color:var(--ink)}.btn:hover{background:var(--sf2)}
.wrapx{max-width:1180px;margin:0 auto;padding:22px 28px 56px;display:grid;gap:20px}
.card{background:var(--sf);border:1px solid var(--ln);border-radius:12px;min-width:0;overflow:hidden}
.card>h2{margin:0;font-size:14px;font-weight:700;padding:14px 18px;border-bottom:1px solid var(--ln);display:flex;justify-content:space-between}
.card>h2 small{font-weight:500;color:var(--mu);font-size:12.5px}
.verdict{display:grid;grid-template-columns:1fr auto;gap:12px 28px;padding:22px 24px;border-left:6px solid var(--fail);background:var(--failb)}
.verdict.pass{border-color:var(--pass);background:var(--passb)}
.verdict h1{margin:0;font-size:28px;letter-spacing:-.02em;color:var(--fail)}.verdict.pass h1{color:var(--pass)}.verdict p{margin:4px 0 0}
.score{text-align:right;min-width:150px}.score .n{font:500 40px/1 var(--mono)}.score .n small{font-size:15px;color:var(--mu)}.score .t{font-size:12.5px;color:var(--mu)}
.meter{height:6px;background:color-mix(in srgb,var(--ink) 12%,transparent);border-radius:6px;margin-top:9px;overflow:hidden}.meter i{display:block;height:100%;background:var(--fail)}.verdict.pass .meter i{background:var(--pass)}
.pipe{display:flex;align-items:flex-start;padding:24px 28px;overflow-x:auto}
.node{display:flex;flex-direction:column;align-items:center;text-align:center;width:104px;flex:none}
.ring{width:54px;height:54px;border-radius:50%;display:grid;place-items:center;border:2px solid var(--ln);background:var(--sf2);color:var(--mu)}
.node b{margin-top:8px;font-size:13.5px}.node span{font-size:12px;color:var(--mu)}.node em{font:500 11.5px var(--mono);font-style:normal;margin-top:3px;color:var(--mu)}
.node.clean .ring{border-color:var(--ac);background:var(--ac);color:#fff}.node.found .ring{border-color:var(--high);color:var(--high);background:var(--sf)}.node.found em{color:var(--high)}
.node.skipped{opacity:.4}.node.locked .ring{border-color:var(--fail);background:var(--fail);color:#fff}.node.open .ring{border-color:var(--pass);background:var(--pass);color:#fff}
.node.locked em{color:var(--fail)}.node.open em{color:var(--pass)}
.conn{flex:1;height:2px;background:var(--ln);margin-top:26px;min-width:20px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);border-bottom:1px solid var(--ln)}.stat{padding:12px 18px;border-right:1px solid var(--ln)}.stat:last-child{border:0}
.stat .n{font:500 24px var(--mono)}.stat .l{font-size:12.5px;color:var(--mu)}
.dist{display:flex;height:8px;background:var(--ln)}.dist i{display:block}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
.s-CRITICAL{background:var(--crit)}.s-HIGH{background:var(--high)}.s-MEDIUM{background:var(--med)}.s-LOW{background:var(--low)}.s-INFO{background:var(--info)}
.s-CRITICALb{background:var(--crit)}.s-HIGHb{background:var(--high)}.s-MEDIUMb{background:var(--med)}.s-LOWb{background:var(--low)}.s-INFOb{background:var(--info)}
.two{display:grid;grid-template-columns:1.3fr 1fr;gap:20px}@media(max-width:860px){.two{grid-template-columns:1fr}.verdict{grid-template-columns:1fr}.score{text-align:left}.stats{grid-template-columns:repeat(3,1fr)}}
.mx{display:grid;grid-template-columns:90px repeat(5,1fr);gap:4px;padding:16px 18px}
.mx>div{padding:8px 4px;text-align:center;font:500 13px var(--mono)}.mx .h{font:600 12px var(--sans);color:var(--mu)}.mx .rl{text-align:left;font:600 12.5px var(--sans);overflow:hidden;text-overflow:ellipsis}.mx .nil{color:var(--mu)}
.cell{border:1px solid var(--ln);border-radius:6px;font:500 13px var(--mono);padding:8px 4px;cursor:pointer;color:var(--ink);background:var(--sf2)}
.s-CRITICALc{background:color-mix(in srgb,var(--crit) var(--n),var(--sf2))}.s-HIGHc{background:color-mix(in srgb,var(--high) var(--n),var(--sf2))}
.s-MEDIUMc{background:color-mix(in srgb,var(--med) var(--n),var(--sf2))}.s-LOWc{background:color-mix(in srgb,var(--low) var(--n),var(--sf2))}.s-INFOc{background:color-mix(in srgb,var(--info) var(--n),var(--sf2))}
.cell:hover{border-color:var(--ink)}
.hs{display:grid;grid-template-columns:1fr 90px 28px;gap:10px;align-items:center;padding:9px 18px;border-bottom:1px solid var(--ln);font-size:12.5px}.hs:last-child{border:0}
.hs .loc{font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.hs b{font:500 13px var(--mono);text-align:right}
.bar{height:6px;background:var(--ln);border-radius:6px;overflow:hidden}.bar i{display:block;height:100%;background:var(--high)}
.empty{padding:30px;text-align:center;color:var(--mu)}
.tools{display:flex;gap:8px;flex-wrap:wrap;padding:14px 18px;align-items:center}
.chip{font:600 12.5px var(--sans);padding:5px 12px;border:1px solid var(--ln);border-radius:20px;background:none;color:var(--ink);cursor:pointer}.chip[aria-pressed=true]{background:var(--ink);color:var(--sf);border-color:var(--ink)}
.tools input,.tools select{font:13px var(--sans);padding:8px 11px;border:1px solid var(--ln);border-radius:8px;background:var(--sf2);color:var(--ink)}.tools input{flex:1;min-width:160px}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;font-size:12px;color:var(--mu);padding:9px 18px;border-block:1px solid var(--ln);white-space:nowrap}
td{padding:10px 18px;border-bottom:1px solid var(--ln);vertical-align:top}tr.r{cursor:pointer}tr.r:hover td{background:var(--sf2)}
tr.r[aria-expanded=true] td{background:var(--sf2)}td.loc{font:12.5px var(--mono);word-break:break-all}
.sev{display:inline-flex;align-items:center;font-weight:600;font-size:12.5px}
.sc{font:12px var(--mono);padding:2px 7px;border-radius:4px;background:var(--sf2);border:1px solid var(--ln)}
.pill{font:700 11px var(--sans);padding:2px 9px;border-radius:20px;background:var(--failb);color:var(--fail);margin-left:6px;white-space:nowrap}
tr.d td{background:var(--sf2)}.dg{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px 24px}
.dg h4{margin:0 0 3px;font-size:12px;color:var(--mu)}.dg p{margin:0}
.foot{padding:11px 18px;font-size:12.5px;color:var(--mu)}
footer{text-align:center;color:var(--mu);font-size:12.5px}
@media print{body{background:#fff}.tools,.btn{display:none}.card{break-inside:avoid}tr.d{display:table-row}}
"""

_JS = """
(function(){
var f={s:'',k:'',q:''},rows=[].slice.call(document.querySelectorAll('tr.r'));
function apply(){var n=0;rows.forEach(function(r){var ok=(!f.s||r.dataset.s===f.s)&&(!f.k||r.dataset.k===f.k)&&(!f.q||r.dataset.q.indexOf(f.q)>-1);
 r.hidden=!ok;if(!ok){r.nextElementSibling.hidden=true;r.setAttribute('aria-expanded','false')}else n++});
 document.getElementById('cnt').textContent=n+' of '+rows.length;document.getElementById('none').hidden=n>0;
 [].forEach.call(document.querySelectorAll('.chip'),function(c){c.setAttribute('aria-pressed',(c.dataset.v||'')===f.s)})}
function tog(r){var d=r.nextElementSibling,o=d.hidden;d.hidden=!o;r.setAttribute('aria-expanded',String(o))}
rows.forEach(function(r){r.onclick=function(){tog(r)};r.onkeydown=function(e){if(e.key==='Enter')tog(r)}});
[].forEach.call(document.querySelectorAll('.chip'),function(c){c.onclick=function(){f.s=c.dataset.v;apply()}});
[].forEach.call(document.querySelectorAll('.cell'),function(c){c.onclick=function(){f.s=c.dataset.s;f.k=c.dataset.k;document.getElementById('fk').value=f.k;apply();document.getElementById('tbl').scrollIntoView({behavior:'smooth',block:'start'})}});
document.getElementById('fk').onchange=function(e){f.k=e.target.value;apply()};
document.getElementById('fq').oninput=function(e){f.q=e.target.value.toLowerCase();apply()};
document.getElementById('pr').onclick=function(){window.print()};apply();
})();
"""

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pipeline-Gate Report · __TITLE__</title>
<style>__CSS__</style>
</head>
<body>
<header>
  <div class="logo"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 2.5 4 5.5v6c0 4.7 3.2 8.6 8 10 4.8-1.4 8-5.3 8-10v-6l-8-3z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>Pipeline-Gate</div>
  <span class="meta">__SCAN__ · __NOW__</span>
  <button class="btn" id="pr">Print / Save PDF</button>
</header>
<div class="wrapx">
  <section class="card">
    <div class="verdict __CLS__">
      <div><h1>__TITLE__</h1><p>__REASON__</p></div>
      <div class="score"><div class="n">__SCORE__<small>/100</small></div><div class="t">Risk score</div>
        <div class="meter" role="img" aria-label="Risk score __SCORE__ of 100"><i style="width:__SCOREW__%"></i></div></div>
    </div>
    <div class="pipe" aria-label="Pipeline stages">__PIPE__</div>
    <div class="stats">__STATS__</div>
    <div class="dist" aria-hidden="true">__DIST__</div>
  </section>
  <div class="two">
    <section class="card"><h2>Risk matrix <small>select a cell to filter</small></h2><div class="mx">__MX__</div></section>
    <section class="card"><h2>Hotspots <small>most affected locations</small></h2>__HOT__</section>
  </div>
  <section class="card" id="tbl"><h2>Findings <small id="cnt"></small></h2>
    <div class="tools">__CHIPS__<select id="fk" aria-label="Scanner"><option value="">All scanners</option>__TOOLS__</select><input id="fq" type="search" placeholder="Search findings" aria-label="Search findings"></div>
    <div class="tw"><table><thead><tr><th>Severity</th><th>Scanner</th><th>Location</th><th>Issue</th></tr></thead><tbody>__ROWS__</tbody></table></div>
    <div class="empty" id="none" hidden>No findings match these filters.</div>
    <div class="foot">Select a row to see why it matters and how to fix it. __TOTAL__ findings in total.</div>
  </section>
  <footer>Generated by Pipeline-Gate</footer>
</div>
<script>__JS__</script>
</body>
</html>
"""