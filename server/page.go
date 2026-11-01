package main

import (
	"fmt"
	"html"
	"path"
	"strings"
)

type target struct {
	key, title, detail string
	match              func(Download) bool
}

var targets = []target{
	{"windows", "Windows", "Windows 10 / 11 · x64", func(d Download) bool { return d.Platform == "win32" }},
	{"mac-arm64", "macOS", "Apple 芯片（M1 及以后）· macOS 14+", func(d Download) bool {
		return d.Platform == "darwin" && d.Arch == "arm64" && d.Format == "dmg"
	}},
	{"mac-x64", "macOS", "Intel 芯片 · macOS 14+", func(d Download) bool {
		return d.Platform == "darwin" && d.Arch == "x64" && d.Format == "dmg"
	}},
	{"linux", "Linux", "Ubuntu 24.04 · x64 · .deb", func(d Download) bool { return d.Platform == "linux" }},
}

// downloadPage recommends the visitor's platform and explains how to open an unsigned
// installer, which is where most first-time users get stuck.
func downloadPage(brand *Brand, release *ReleaseState) string {
	name := "客户端下载"
	if brand != nil {
		name = brand.Name
	}
	name = html.EscapeString(name)
	var cards strings.Builder
	unsigned := false
	if release != nil {
		for _, t := range targets {
			for _, d := range release.Downloads {
				if !t.match(d) {
					continue
				}
				unsigned = unsigned || !d.Signed && d.Platform != "linux"
				base := html.EscapeString(path.Base(d.File))
				fmt.Fprintf(&cards, `<a class="card" data-target="%s" href="/files/%s" download="%s"><span class="os">%s</span><span class="detail">%s</span><span class="meta">%s · %.1f MB</span></a>`,
					t.key, html.EscapeString(d.File), base, t.title, t.detail, base, float64(d.Bytes)/1048576)
				break
			}
		}
	}
	sub := "暂无可下载的版本。"
	if release != nil {
		sub = fmt.Sprintf("最新版本 %s · 发布于 %s", html.EscapeString(release.Version), html.EscapeString(release.PublishedAt[:min(10, len(release.PublishedAt))]))
	}
	notes := ""
	if unsigned {
		notes = `<div class="notes"><strong>第一次打开时系统会拦一下，按下面做一次就好</strong>
<p><b>Windows</b>：出现“Windows 已保护你的电脑”时，点“更多信息”，再点“仍要运行”。</p>
<p><b>macOS</b>：把应用拖进“应用程序”，双击打开。提示“无法验证开发者”或“已损坏”时，打开“系统设置 → 隐私与安全性”，在页面最下方点“仍要打开”，输入开机密码确认。用过 TUN 模式的旧版本无法直接覆盖（提示项目被“锁定”）：先把旧版拖到废纸篓（输入开机密码），再拖入新版。</p>
<p>装好以后，新版本会显示在客户端首页，点“立即更新”即可，不用再来这里下载。</p>
<p><b>Linux</b>：在终端运行 <code>sudo apt install ./下载的文件.deb</code>。</p></div>`
	}
	return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + name + ` · 下载</title><style>
:root{--bg:#f6f7fb;--fg:#14161f;--muted:#6b7084;--card:#fff;--line:#e3e5ee;--accent:#4f5dff}
@media (prefers-color-scheme:dark){:root{--bg:#0f1117;--fg:#eceef6;--muted:#9aa0b4;--card:#171a23;--line:#262a37;--accent:#7c87ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:880px;margin:0 auto;padding:56px 16px}h1{font-size:30px;margin:0 0 4px}p.sub{color:var(--muted);margin:0 0 32px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.card{display:flex;flex-direction:column;gap:4px;padding:18px;border:1px solid var(--line);border-radius:14px;background:var(--card);color:inherit;text-decoration:none}
.card:hover{border-color:var(--accent)}.card.recommended{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 18%,transparent);grid-column:1/-1;padding:24px}
.recommended .os{font-size:22px}.os{font-weight:650;font-size:18px}.detail,.meta{color:var(--muted);font-size:13px}
.tag{align-self:flex-start;font-size:12px;color:#fff;background:var(--accent);border-radius:999px;padding:2px 10px}
.notes{margin-top:32px;padding:16px 18px;border-radius:12px;background:var(--card);border:1px solid var(--line);font-size:14px}
.notes p{margin:8px 0 0}.notes code{font-size:13px}
</style></head><body><main>
<h1>` + name + `</h1><p class="sub">` + sub + `</p>
<div class="grid">` + cards.String() + `</div>` + notes + `
</main><script>
(()=>{const ua=navigator.userAgent;let k=/Windows/.test(ua)?'windows':/Mac/.test(ua)?'mac':/Linux/.test(ua)&&!/Android/.test(ua)?'linux':'';
const mark=t=>{const c=document.querySelector('[data-target="'+t+'"]');if(c){c.classList.add('recommended');c.insertAdjacentHTML('afterbegin','<span class="tag">推荐下载</span>');c.parentNode.prepend(c)}};
if(k!=='mac')return k&&mark(k);
const d=navigator.userAgentData;if(d&&d.getHighEntropyValues)d.getHighEntropyValues(['architecture']).then(v=>mark(v.architecture==='arm'?'mac-arm64':'mac-x64')).catch(()=>mark('mac-arm64'));else mark('mac-arm64');})();
</script></body></html>`
}

// adminPage looks up a user's telemetry by email or a report by its code. The token
// is the /admin bearer token (tools/admin-token.mjs) and stays in this tab only.
const adminPage = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>用户排查</title><style>
:root{--bg:#f6f7fb;--fg:#14161f;--muted:#6b7084;--card:#fff;--line:#e3e5ee;--bad:#c62828;--ok:#2e7d32}
@media (prefers-color-scheme:dark){:root{--bg:#0f1117;--fg:#eceef6;--muted:#9aa0b4;--card:#171a23;--line:#262a37;--bad:#ef5350;--ok:#66bb6a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}form{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
input,button{font:inherit;padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:inherit}button{cursor:pointer}
input[name=q]{flex:1;min-width:220px}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}th{color:var(--muted);font-weight:500}
.bad{color:var(--bad)}.ok{color:var(--ok)}pre{white-space:pre-wrap;word-break:break-all;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;font-size:12px}
.muted{color:var(--muted)}.wrap{overflow-x:auto}
</style></head><body><main><h2>用户排查</h2>
<form id="f"><input name="token" type="password" placeholder="管理令牌" autocomplete="off"><input name="q" placeholder="用户邮箱，或 6 位问题编号"><input name="days" type="number" min="1" max="31" value="7" style="width:80px"><button>查询</button></form>
<div id="out" class="muted">输入邮箱查看该用户最近的连接记录；输入问题编号查看用户提交的诊断报告。</div>
<script>
const f=document.getElementById('f'),out=document.getElementById('out');
f.token.value=sessionStorage.getItem('token')||'';
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';');
const get=async p=>{const r=await fetch(p,{headers:{Authorization:'Bearer '+f.token.value}});if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||r.status);return r.json()};
const fields=e=>Object.entries(e).filter(([k])=>k!=='type'&&k!=='at').map(([k,v])=>'<span class="'+(v===false||k==='code'?'bad':v===true?'ok':'')+'">'+esc(k)+'='+esc(v)+'</span>').join(' ');
const when=v=>v?new Date(v).toLocaleString():'';
f.onsubmit=async ev=>{ev.preventDefault();sessionStorage.setItem('token',f.token.value);const q=f.q.value.trim();out.textContent='查询中…';
try{if(/^[2-9A-HJ-NP-Z]{6}$/i.test(q)){const r=await get('/admin/reports/'+q.toUpperCase());
out.innerHTML='<p>'+esc(r.email)+' · '+esc(r.platform)+' '+esc(r.arch)+' '+esc(r.os)+' · 版本 '+esc(r.version)+' · '+when(r.receivedAt)+' · IP '+esc(r.ip)+'</p>'+(r.note?'<p>留言：'+esc(r.note)+'</p>':'')+
'<h3>网络自检</h3><div class="wrap"><table>'+(r.checks||[]).map(c=>'<tr><td>'+esc(c.name)+'</td><td>'+fields(c)+'</td></tr>').join('')+'</table></div>'+
'<h3>最近事件</h3><div class="wrap"><table>'+(r.events||[]).slice().reverse().map(e=>'<tr><td>'+when(e.at)+'</td><td>'+esc(e.type)+'</td><td>'+fields(e)+'</td></tr>').join('')+'</table></div>';return}
const p='email='+encodeURIComponent(q)+'&days='+f.days.value;const [events,reports]=await Promise.all([get('/admin/events?'+p),get('/admin/reports?'+p)]);
out.innerHTML=(reports.length?'<h3>问题报告</h3><p>'+reports.map(r=>'<a href="#" data-code="'+esc(r.code)+'">'+esc(r.code)+'</a> '+when(r.receivedAt)+' '+esc(r.note)).join('<br>')+'</p>':'')+
'<h3>事件（'+events.length+'）</h3><div class="wrap"><table><tr><th>时间</th><th>类型</th><th>详情</th><th>客户端</th><th>IP</th></tr>'+
events.map(e=>'<tr><td>'+when(e.event.at||e.receivedAt)+'</td><td>'+esc(e.event.type)+'</td><td>'+fields(e.event)+'</td><td>'+esc(e.version)+' '+esc(e.platform)+' '+esc(e.os)+'</td><td>'+esc(e.ip)+'</td></tr>').join('')+'</table></div>';
out.querySelectorAll('[data-code]').forEach(a=>a.onclick=e=>{e.preventDefault();f.q.value=a.dataset.code;f.requestSubmit()});
}catch(e){out.textContent='查询失败：'+e.message}};
</script></main></body></html>`
