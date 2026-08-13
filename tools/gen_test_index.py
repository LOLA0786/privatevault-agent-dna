#!/usr/bin/env python3
"""Generate a single-file HTML index of every test that actually collects.

Ground truth is `pytest --collect-only -q`. Docstrings are enriched from AST.
Nothing is hand-maintained, so the page cannot drift from the suite.
"""
from __future__ import annotations

import ast
import html
import json
import pathlib
import subprocess
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "test-index.html"


def collected() -> list[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        capture_output=True, text=True, cwd=ROOT,
    )
    ids = [ln.strip() for ln in proc.stdout.splitlines() if "::" in ln]
    if not ids:
        sys.exit("no tests collected -- run this from the repo root")
    return ids


def docstrings() -> dict[tuple[str, str], str]:
    out: dict[tuple[str, str], str] = {}
    for p in ROOT.rglob("test_*.py"):
        if any(part in {".git", ".venv", "node_modules"} for part in p.parts):
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = str(p.relative_to(ROOT))
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if n.name.startswith("test_"):
                    doc = ast.get_docstring(n) or ""
                    out[(rel, n.name)] = doc.strip().split("\n")[0]
    return out


def main() -> None:
    ids = collected()
    docs = docstrings()
    groups: dict[str, list[dict]] = defaultdict(list)
    for tid in ids:
        path, _, rest = tid.partition("::")
        func = rest.split("[")[0]
        param = rest[len(func):]
        groups[path].append({
            "n": rest,
            "d": docs.get((path, func), ""),
            "p": bool(param),
        })

    data = [
        {"f": f, "t": sorted(groups[f], key=lambda x: x["n"])}
        for f in sorted(groups)
    ]
    OUT.write_text(
        TEMPLATE.replace("__DATA__", json.dumps(data))
        .replace("__TOTAL__", str(len(ids)))
        .replace("__FILES__", str(len(groups))),
        encoding="utf-8",
    )
    print(f"wrote {OUT}  ({len(ids)} tests across {len(groups)} files)")


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PrivateVault - the suite, in full</title>
<style>
:root{--paper:#EFEDE7;--panel:#F8F7F4;--ink:#12181D;--ink-2:#4C5760;--ink-3:#8A939B;
--rule:#C6C2B8;--stop:#A32A20;--pass:#1F6153;
--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.5}
.wrap{max-width:1180px;margin:0 auto;padding:30px 24px 60px}
header{border-bottom:2px solid var(--ink);padding-bottom:16px;margin-bottom:18px}
.eyebrow{font-family:var(--mono);font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink-2);margin:0 0 10px}
h1{font-size:clamp(23px,3.4vw,34px);line-height:1.1;letter-spacing:-.02em;margin:0 0 10px;max-width:24ch}
.lede{color:var(--ink-2);max-width:70ch;margin:0;font-size:16px}
.stats{display:flex;flex-wrap:wrap;gap:20px;margin-top:14px;font-family:var(--mono);font-size:11px;color:var(--ink-2)}
.stats b{color:var(--ink)}
.bar{position:sticky;top:0;background:var(--paper);padding:14px 0;border-bottom:1px solid var(--rule);z-index:5;
display:flex;gap:12px;flex-wrap:wrap;align-items:center}
#q{flex:1 1 320px;font-family:var(--mono);font-size:13px;padding:9px 12px;border:1px solid var(--ink);background:var(--panel);color:var(--ink)}
#q:focus{outline:2px solid var(--stop);outline-offset:-2px}
.count{font-family:var(--mono);font-size:11px;color:var(--ink-2);white-space:nowrap}
.btn{appearance:none;border:1px solid var(--ink);background:transparent;font-family:var(--mono);font-size:10.5px;
letter-spacing:.08em;text-transform:uppercase;padding:8px 12px;cursor:pointer;color:var(--ink)}
.btn:hover{background:var(--ink);color:var(--panel)}
.file{border:1px solid var(--rule);background:var(--panel);margin-top:14px}
.fh{display:flex;justify-content:space-between;gap:12px;align-items:baseline;padding:10px 14px;
background:#E6E3DB;cursor:pointer;font-family:var(--mono);font-size:12px}
.fh .c{color:var(--ink-3);font-size:10.5px;white-space:nowrap}
.file.shut .tl{display:none}
.tl{margin:0;padding:0;list-style:none}
.tl li{display:grid;grid-template-columns:14px 1fr;gap:9px;padding:6px 14px;border-top:1px solid var(--rule);font-size:13px}
.tl .m{font-family:var(--mono);font-size:10px;color:var(--pass);line-height:1.7}
.tl .n{font-family:var(--mono);font-size:12px;word-break:break-word}
.tl .d{display:block;color:var(--ink-3);font-family:var(--sans);font-size:12px;margin-top:2px}
mark{background:#F4E2E0;color:var(--stop)}
.none{padding:26px 14px;color:var(--ink-3);font-size:14px}
.foot{margin-top:34px;padding-top:14px;border-top:1px solid var(--rule);font-family:var(--mono);
font-size:11px;color:var(--ink-3);display:flex;flex-wrap:wrap;gap:18px}
</style></head><body><div class="wrap">
<header>
<p class="eyebrow">PrivateVault - Pentaprime Solutions</p>
<h1>Every claim in this project points at a test. Here is every test.</h1>
<p class="lede">Generated directly from <code>pytest --collect-only</code>, not maintained by hand, so this page cannot drift from what actually runs. Search a control, a reason code, or a behaviour and read the test that proves it.</p>
<div class="stats"><span><b>__TOTAL__</b> tests</span><span><b>__FILES__</b> files</span><span>generated from the suite, not written</span></div>
</header>
<div class="bar">
<input id="q" type="search" placeholder="Search: consume, peer, fail_closed, maker, digest..." autocomplete="off">
<span class="count" id="cnt"></span>
<button class="btn" id="ex">Expand all</button>
<button class="btn" id="co">Collapse all</button>
</div>
<div id="out"></div>
<div class="foot"><span>Chandan Galani - Founder</span><span>privatevault.ai</span><span>Regenerate: python tools/gen_test_index.py</span></div>
</div>
<script>
var DATA=__DATA__;
var out=document.getElementById("out"),q=document.getElementById("q"),cnt=document.getElementById("cnt");
function esc(s){return s.replace(/&/g,"&amp;").replace(/</g,"&lt;")}
function hl(s,t){if(!t)return esc(s);var i=s.toLowerCase().indexOf(t);if(i<0)return esc(s);
 return esc(s.slice(0,i))+"<mark>"+esc(s.slice(i,i+t.length))+"</mark>"+esc(s.slice(i+t.length))}
function render(t){
 t=(t||"").trim().toLowerCase();var shown=0,html="";
 DATA.forEach(function(g){
  var hit=g.t.filter(function(x){
   return !t||x.n.toLowerCase().indexOf(t)>=0||(x.d||"").toLowerCase().indexOf(t)>=0||g.f.toLowerCase().indexOf(t)>=0});
  if(!hit.length)return;shown+=hit.length;
  html+='<div class="file'+(t?"":" shut")+'"><div class="fh"><span>'+hl(g.f,t)+
   '</span><span class="c">'+hit.length+(hit.length===g.t.length?"":" of "+g.t.length)+'</span></div><ul class="tl">'+
   hit.map(function(x){return '<li><span class="m">'+(x.p?"[]":"\u00b7")+'</span><span class="n">'+hl(x.n,t)+
    (x.d?'<span class="d">'+hl(x.d,t)+'</span>':'')+'</span></li>'}).join("")+'</ul></div>'});
 out.innerHTML=html||'<p class="none">Nothing matches that.</p>';
 cnt.textContent=shown+" shown";
 out.querySelectorAll(".fh").forEach(function(h){h.addEventListener("click",function(){h.parentNode.classList.toggle("shut")})})}
q.addEventListener("input",function(){render(q.value)});
document.getElementById("ex").addEventListener("click",function(){out.querySelectorAll(".file").forEach(function(f){f.classList.remove("shut")})});
document.getElementById("co").addEventListener("click",function(){out.querySelectorAll(".file").forEach(function(f){f.classList.add("shut")})});
render("");
</script></body></html>
"""

if __name__ == "__main__":
    main()
