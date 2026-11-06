"""Write a single self-contained HTML explorer from results.json.

Usage: python -m swarmforensics.explorer out/results.json out/explorer.html
"""
import json
import sys

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Swarm Forensics Explorer</title>
<style>
:root{--bg:#fbfaf7;--fg:#1d1d1b;--mut:#6b6a66;--line:#e2dfd8;--card:#fff;--acc:#2f5d8a;--hot:#b4472f;--code:#f3f1ec}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe7;--mut:#a09e98;--line:#34332f;--card:#1f1f1d;--acc:#7fb0de;--hot:#e5866d;--code:#262624}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 80px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 8px;border-bottom:1px solid var(--line);padding-bottom:6px}
p.lead{color:var(--mut);margin:0 0 18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.card b{display:block;font-size:22px}.card span{color:var(--mut);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}td.n{text-align:right;font-variant-numeric:tabular-nums}
.wrap{overflow-x:auto}
pre{background:var(--code);padding:10px;border-radius:6px;white-space:pre-wrap;word-break:break-all;font-size:12.5px;margin:6px 0 0;max-height:260px;overflow:auto}
.tag{display:inline-block;background:var(--code);border-radius:10px;padding:1px 8px;margin:2px 3px 2px 0;font-size:12px}
input{width:100%;max-width:420px;padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);font:inherit}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:6px 0}
summary{cursor:pointer}summary .mut{color:var(--mut)}
a{color:var(--acc)}.hot{color:var(--hot);font-weight:600}
canvas{width:100%;height:520px;background:var(--card);border:1px solid var(--line);border-radius:8px;display:block}
.note{color:var(--mut);font-size:13px}
</style></head><body><main>
<h1>Swarm Forensics Explorer</h1>
<p class="lead">Coding-style families, shared secrets and self-chosen names in the public Swarm Traces dump (redacted). Built for the Apart Research Swarm Alignment Hackathon, Nov 2026. Everything here is computed from the redacted public data; no identity is recovered.</p>
<div class="cards" id="cards"></div>

<h2>Does the method work? (validation without ground truth)</h2>
<p class="note">Families are built from code style only: every secret, service and repo label is replaced by its type before fingerprinting. So "do two payloads of the same family touch the same secret?" is an independent check.</p>
<div class="wrap"><table id="val"></table></div>

<h2>Secret-sharing clusters</h2>
<p class="note">Families linked because they use the same credential. Secrets seen in more than <span id="maxfam"></span> families are left out (broadcast to everyone, they would glue the whole graph).</p>
<canvas id="graph"></canvas>
<p class="note">Node = family (area ~ payload count), edge = at least one shared secret. Drag to move. Largest clusters listed below.</p>
<div id="clusters"></div>

<h2>One lineage, several names</h2>
<p class="note">Self-chosen User-Agent names that survive redaction, grouped by the coding-style family of the payload that carries them.</p>
<div class="wrap"><table id="names"></table></div>

<h2>Families</h2>
<input id="q" placeholder="Filter: family id, trait, artifact (e.g. CREDENTIAL 1, XMLHttpRequest)">
<div id="fams"></div>

<h2>Artifacts reused across families</h2>
<div class="wrap"><table id="cross"></table></div>
</main>
<script>
const R=__DATA__;
const $=s=>document.querySelector(s),el=(t,a={},...c)=>{const e=document.createElement(t);Object.assign(e,a);for(const x of c)e.append(x);return e};
const S=R.summary,V=R.validation,fmt=x=>typeof x==='number'?x.toLocaleString('en'):x,pct=x=>(100*x).toFixed(1)+'%';
[["rows",S.rows,"rows in the dump"],["docs",S.docs,"payload documents"],["families",S.families,"style families"],["f10",S.families_10plus,"families with 10+ payloads"],
 ["sec",S.secret_artifacts,"distinct secrets"],["secx",S.secret_cross_family,"secrets used by 3+ families"],["names",S.self_chosen_names,"self-chosen names"]]
 .forEach(([k,v,l])=>$('#cards').append(el('div',{className:'card'},el('b',{textContent:fmt(v)}),el('span',{textContent:l}))));
const ci=w=>`${pct(w[0])} [${pct(w[1])}–${pct(w[2])}]`;
const vt=$('#val');vt.innerHTML='<tr><th>Test</th><th>Same group</th><th>Different groups</th><th>Lift</th></tr>';
[["Style families: share any artifact",V.style_families_any],["Style families: share a secret",V.style_families_secret],
 ["Baseline, exact code skeleton: share a secret",V.baseline_exact_secret],["Baseline, trait signature: share a secret",V.baseline_traits_secret]]
 .forEach(([n,v])=>vt.append(el('tr',{},el('td',{textContent:n}),el('td',{textContent:ci(v.same_share)}),el('td',{textContent:ci(v.cross_share)}),el('td',{className:'n hot',textContent:v.lift.toFixed(1)+'×'}))));
const sh=V.split_half,st=V.seed_stability;
vt.append(el('tr',{},el('td',{textContent:`Split-half re-linking (${sh.queries} queries, pool ${fmt(sh.pool)}): nearest second half is from the same family`}),el('td',{textContent:ci(sh.nearest_is_same_family)}),el('td',{textContent:'random: '+pct(sh.random_baseline_same_family)}),el('td',{className:'n hot',textContent:(sh.nearest_is_same_family[0]/sh.random_baseline_same_family).toFixed(0)+'×'})));
vt.append(el('tr',{},el('td',{textContent:'Seed stability: same-family pairs kept with another hash seed'}),el('td',{textContent:ci(st.pairs_kept_seed0_to_seed1)}),el('td',{textContent:'reverse: '+ci(st.pairs_kept_seed1_to_seed0)}),el('td',{textContent:''})));
$('#maxfam').textContent=S.secret_graph_max_families_per_secret;
R.secret_clusters.slice(0,12).forEach((c,i)=>$('#clusters').append(el('details',{},el('summary',{innerHTML:`Cluster ${i+1}: <b>${c.families}</b> families, ${fmt(c.docs)} payloads <span class="mut">— e.g. ${c.secrets.slice(0,3).join(', ')}</span>`}),el('div',{className:'note',textContent:'Families: '+c.members.join(', ')}))));
const nt=$('#names');nt.innerHTML='<tr><th>Family</th><th>Payloads</th><th>Names seen (count)</th></tr>';
R.multi_name_families.forEach(m=>nt.append(el('tr',{},el('td',{textContent:m.family}),el('td',{className:'n',textContent:fmt(m.family_docs)}),el('td',{textContent:Object.entries(m.names).map(([k,v])=>`${k} (${v})`).join(', ')}))));
function drawFams(q){const box=$('#fams');box.innerHTML='';q=q.toLowerCase();let n=0;
 for(const f of R.families){const hay=(f.id+' '+Object.keys(f.traits).join(' ')+' '+f.top_artifacts.map(a=>a[0]).join(' ')).toLowerCase();if(q&&!hay.includes(q))continue;if(++n>60)break;
  const d=el('details',{},el('summary',{innerHTML:`<b>${f.id}</b> · ${fmt(f.docs)} payloads · ${fmt(f.variants)} variants · ${f.n_secrets} secrets <span class="mut">${Object.keys(f.traits).slice(0,4).join(' · ')}</span>`}));
  const t=el('div');Object.entries(f.traits).forEach(([k,v])=>t.append(el('span',{className:'tag',textContent:`${k} ${Math.round(v*100)}%`})));
  d.append(t,el('div',{className:'note',textContent:'Most used artifacts: '+f.top_artifacts.slice(0,8).map(a=>`${a[0]} ×${a[1]}`).join(', ')}),el('div',{className:'note',textContent:'Example ('+f.example_id+'):'}),el('pre',{textContent:f.example}));box.append(d)}
 if(!n)box.append(el('p',{className:'note',textContent:'No family matches.'}))}
drawFams('');$('#q').addEventListener('input',e=>drawFams(e.target.value));
const ct=$('#cross');ct.innerHTML='<tr><th>Artifact</th><th>Type</th><th>Payloads</th><th>Families</th><th>Main families</th></tr>';
R.cross_family_artifacts.slice(0,80).forEach(a=>ct.append(el('tr',{},el('td',{textContent:a.artifact}),el('td',{textContent:a.type}),el('td',{className:'n',textContent:fmt(a.docs)}),el('td',{className:'n',textContent:fmt(a.families)}),el('td',{className:'note',textContent:a.top_families.slice(0,4).map(x=>x[0]+'×'+x[1]).join(', ')}))));
// tiny force layout
(function(){const cv=$('#graph'),dpr=devicePixelRatio||1,W=cv.clientWidth,H=cv.clientHeight;cv.width=W*dpr;cv.height=H*dpr;const g=cv.getContext('2d');g.scale(dpr,dpr);
 const size={};R.families.forEach(f=>size[f.id]=f.docs);const ids=new Set();R.secret_graph_edges.forEach(e=>{ids.add(e.a);ids.add(e.b)});
 const N=[...ids].map(id=>({id,x:W/2+(Math.random()-.5)*W*.8,y:H/2+(Math.random()-.5)*H*.8,vx:0,vy:0,r:2+Math.sqrt(size[id]||3)/3}));const ix={};N.forEach((n,i)=>ix[n.id]=i);
 const E=R.secret_graph_edges.map(e=>[ix[e.a],ix[e.b],e.shared_secrets]);
 const css=getComputedStyle(document.documentElement),acc=css.getPropertyValue('--acc'),line=css.getPropertyValue('--line'),mut=css.getPropertyValue('--mut');
 let drag=null,ticks=0;
 function step(){for(let i=0;i<N.length;i++)for(let j=i+1;j<N.length;j++){const a=N[i],b=N[j];let dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy+.01;if(d2>40000)continue;const f=60/d2;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f}
  for(const[i,j]of E){const a=N[i],b=N[j],dx=b.x-a.x,dy=b.y-a.y;a.vx+=dx*.004;a.vy+=dy*.004;b.vx-=dx*.004;b.vy-=dy*.004}
  for(const n of N){if(n===drag)continue;n.vx+=(W/2-n.x)*.002;n.vy+=(H/2-n.y)*.002;n.x+=n.vx*=.6;n.y+=n.vy*=.6;n.x=Math.max(n.r,Math.min(W-n.r,n.x));n.y=Math.max(n.r,Math.min(H-n.r,n.y))}}
 function draw(){g.clearRect(0,0,W,H);g.strokeStyle=line;g.lineWidth=.6;g.beginPath();for(const[i,j]of E){g.moveTo(N[i].x,N[i].y);g.lineTo(N[j].x,N[j].y)}g.stroke();
  g.fillStyle=acc;for(const n of N){g.beginPath();g.arc(n.x,n.y,n.r,0,7);g.fill()}g.fillStyle=mut;g.font='11px system-ui';for(const n of N)if(n.r>9)g.fillText(n.id,n.x+n.r+2,n.y+3)}
 function loop(){if(ticks++<400||drag){step();draw();requestAnimationFrame(loop)}}loop();
 const pos=e=>{const b=cv.getBoundingClientRect();return[e.clientX-b.left,e.clientY-b.top]};
 cv.addEventListener('pointerdown',e=>{const[x,y]=pos(e);drag=N.find(n=>(n.x-x)**2+(n.y-y)**2<(n.r+4)**2)||null;if(drag){ticks=0;loop()}});
 cv.addEventListener('pointermove',e=>{if(drag){[drag.x,drag.y]=pos(e)}});addEventListener('pointerup',()=>drag=null)})();
</script></body></html>"""


def main(src, dst):
    data = json.load(open(src, encoding="utf-8"))
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(PAGE.replace("__DATA__", payload))
    print("wrote", dst)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
