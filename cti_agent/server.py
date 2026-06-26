"""Cyber Threat Intel Agent web dashboard — stdlib http.server, no dependencies.

Routes:
    GET  /                 dashboard UI
    POST /api/sweep        trigger the agent, return the latest report (JSON)
    GET  /api/report       return the last cached report (JSON), or 404
    GET  /healthz          liveness

Run:  python3 -m cti_agent.server   (then open http://localhost:8077)
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .agent import CTIAgent

_STATE = {"report": None, "running": False, "error": None}
_LOCK = threading.Lock()


def _run_sweep():
    with _LOCK:
        if _STATE["running"]:
            return
        _STATE["running"] = True
        _STATE["error"] = None
    try:
        _STATE["report"] = CTIAgent().run_sweep()
    except Exception as exc:  # noqa: BLE001
        _STATE["error"] = str(exc)
    finally:
        _STATE["running"] = False


INDEX_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber Threat Intel Agent</title>
<style>
:root{--bg:#0b0f17;--panel:#131a26;--panel2:#0f1622;--line:#222e44;--txt:#dbe5f3;
--muted:#7e8aa0;--accent:#3ea6ff;--crit:#ff4d5e;--high:#ff9f43;--med:#ffd24d;--low:#48d49b;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:20px 28px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:16px;flex-wrap:wrap;background:linear-gradient(180deg,#0e1420,#0b0f17)}
h1{font-size:20px;margin:0;letter-spacing:.3px}
.logo{width:34px;height:34px;border-radius:8px;background:radial-gradient(circle at 30% 30%,#3ea6ff,#1b4f8a);
display:flex;align-items:center;justify-content:center;font-weight:700;color:#031021}
.sub{color:var(--muted);font-size:13px}
button{background:var(--accent);color:#04121f;border:0;padding:10px 18px;border-radius:8px;
font-weight:600;cursor:pointer;font-size:14px}button:disabled{opacity:.5;cursor:wait}
.meta{margin-left:auto;text-align:right;font-size:12px;color:var(--muted)}
main{padding:22px 28px;display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
@media(max-width:1050px){main{grid-template-columns:1fr}}
.col{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden;
display:flex;flex-direction:column;min-height:240px}
.col h2{margin:0;padding:14px 16px;font-size:15px;border-bottom:1px solid var(--line);
display:flex;align-items:center;gap:8px}
.dot{width:9px;height:9px;border-radius:50%}
.Financial .dot{background:#48d49b}.Healthcare .dot{background:#3ea6ff}.Government .dot{background:#c08cff}
.brief{padding:12px 16px;color:#b9c6db;font-size:13.5px;background:var(--panel2);border-bottom:1px solid var(--line)}
.count{margin-left:auto;font-size:12px;color:var(--muted);font-weight:400}
.items{padding:8px 12px;overflow:auto;flex:1}
.card{border:1px solid var(--line);border-radius:9px;padding:11px 12px;margin:9px 0;background:#0f1521}
.card .t{font-weight:600;font-size:13.5px;margin-bottom:5px}
.badges{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:7px}
.badge{font-size:10.5px;padding:2px 7px;border-radius:20px;border:1px solid var(--line);color:var(--muted)}
.sev{font-weight:700;color:#04121f}
.Critical{background:var(--crit)}.High{background:var(--high)}.Medium{background:var(--med)}
.Low{background:var(--low)}.Unknown{background:#46546e;color:#fff}
.ransom{background:#ff4d5e;color:#fff;border:0}
.live{background:#103a2a;border-color:#1f6f4a;color:#48d49b}
.when{font-size:11px;color:var(--muted);margin:6px 0 2px}
.when b{color:#b9c6db;font-weight:600}
.an{font-size:12.5px;color:#cdd8ea;margin:4px 0}
.ac{font-size:12px;color:#8fe0bf;margin-top:5px}.ac b{color:#48d49b}
.src a{color:var(--accent);text-decoration:none;font-size:11.5px}
.empty{padding:24px 16px;color:var(--muted);font-size:13px;text-align:center}
.bar{height:3px;background:linear-gradient(90deg,#3ea6ff,#48d49b);width:0;transition:width .3s}
.err{color:var(--high);font-size:12px;padding:0 28px}
</style></head><body>
<header>
  <div class="logo">CTI</div>
  <div><h1>Cyber Threat Intel Agent</h1><div class="sub">AI threat-intelligence agent · Financial · Healthcare · Government</div></div>
  <button id="run">▶ Run Intelligence Sweep</button>
  <div class="meta" id="meta">No sweep run yet.</div>
</header>
<div class="bar" id="bar"></div>
<div class="err" id="err"></div>
<main id="main">
  <div class="col Financial"><h2><span class="dot"></span>Financial<span class="count" id="c-Financial"></span></h2>
    <div class="brief" id="b-Financial">Run a sweep to populate this sector.</div>
    <div class="items" id="i-Financial"></div></div>
  <div class="col Healthcare"><h2><span class="dot"></span>Healthcare<span class="count" id="c-Healthcare"></span></h2>
    <div class="brief" id="b-Healthcare">Run a sweep to populate this sector.</div>
    <div class="items" id="i-Healthcare"></div></div>
  <div class="col Government"><h2><span class="dot"></span>Government<span class="count" id="c-Government"></span></h2>
    <div class="brief" id="b-Government">Run a sweep to populate this sector.</div>
    <div class="items" id="i-Government"></div></div>
</main>
<script>
const $=id=>document.getElementById(id);
const esc=s=>(s||"").replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function when(s){
  if(!s)return"";
  const d=new Date(s); if(isNaN(d))return esc(s);
  const days=Math.floor((Date.now()-d)/86400000);
  const age=days<=0?"today":days===1?"1 day ago":days+" days ago";
  return `${d.toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'})} · ${age}`;
}
function render(rep){
  const l=rep.llm.enabled?`LLM: ${rep.llm.model}`:"LLM: off (heuristics)";
  $("meta").innerHTML=`Generated ${esc(rep.generated_at)}<br>${esc(l)} · ${rep.total_raw} raw items · ${esc(rep.sources.join(", "))}`;
  $("err").textContent=(rep.source_errors||[]).join(" | ");
  for(const sec of ["Financial","Healthcare","Government"]){
    const d=rep.sectors[sec]; $("c-"+sec).textContent=d.count+" threats";
    $("b-"+sec).textContent=d.briefing;
    const box=$("i-"+sec);
    if(!d.items.length){box.innerHTML='<div class="empty">No threats mapped this sweep.</div>';continue;}
    box.innerHTML=d.items.map(it=>`<div class="card">
      <div class="t">${esc(it.title)}</div>
      <div class="badges">
        <span class="badge sev ${esc(it.severity)}">${esc(it.severity)}</span>
        ${it.active?`<span class="badge live" title="${esc(it.status||'Currently active')}">● ACTIVE</span>`:''}
        ${it.ransomware?'<span class="badge ransom">RANSOMWARE</span>':''}
        <span class="badge">${esc(it.source)}</span>
        ${(it.tags||[]).slice(0,2).map(t=>`<span class="badge">${esc(t)}</span>`).join("")}
      </div>
      <div class="when"><b>Reported:</b> ${it.published?when(it.published):"—"}${it.status?` · ${esc(it.status)}`:""}</div>
      <div class="an">${esc(it.analysis)}</div>
      <div class="ac"><b>Action:</b> ${esc(it.action)}</div>
      <div class="src">${it.url?`<a href="${esc(it.url)}" target="_blank" rel="noopener">${esc(it.url)}</a>`:""}</div>
    </div>`).join("");
  }
}
async function sweep(){
  const b=$("run");b.disabled=true;b.textContent="⏳ Sweeping…";
  $("bar").style.width="35%";
  try{
    const r=await fetch("/api/sweep",{method:"POST"});
    $("bar").style.width="80%";
    const rep=await r.json();
    if(rep.error){$("err").textContent=rep.error;}else{render(rep);}
  }catch(e){$("err").textContent="Sweep failed: "+e;}
  $("bar").style.width="100%";setTimeout(()=>$("bar").style.width="0",600);
  b.disabled=false;b.textContent="▶ Run Intelligence Sweep";
}
$("run").addEventListener("click",sweep);
// load cached report if present
fetch("/api/report").then(r=>r.ok?r.json():null).then(r=>{if(r)render(r);});
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):  # quieter console
        pass

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        elif self.path == "/healthz":
            self._send(200, json.dumps({"ok": True}))
        elif self.path == "/api/report":
            if _STATE["report"]:
                self._send(200, json.dumps(_STATE["report"]))
            else:
                self._send(404, json.dumps({"error": "no report yet"}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path == "/api/sweep":
            _run_sweep()  # synchronous: returns when the agent finishes
            if _STATE["error"]:
                self._send(500, json.dumps({"error": _STATE["error"]}))
            else:
                self._send(200, json.dumps(_STATE["report"]))
        else:
            self._send(404, json.dumps({"error": "not found"}))


def main(host="127.0.0.1", port=8077):
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"Cyber Threat Intel Agent dashboard → http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        srv.shutdown()


if __name__ == "__main__":
    main()
