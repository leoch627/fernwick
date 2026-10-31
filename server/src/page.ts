import type { Brand, Download } from './payloads';

const escape = (value: string) => value.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const size = (bytes: number) => `${(bytes / 1048576).toFixed(1)} MB`;

const targets: { key: string; title: string; detail: string; match: (d: Download) => boolean }[] = [
  { key: 'windows', title: 'Windows', detail: 'Windows 11 · x64', match: d => d.platform === 'win32' },
  { key: 'mac-arm64', title: 'macOS', detail: 'Apple 芯片 (M 系列) · macOS 14+', match: d => d.platform === 'darwin' && d.arch === 'arm64' && d.format === 'dmg' },
  { key: 'mac-x64', title: 'macOS', detail: 'Intel 芯片 · macOS 14+', match: d => d.platform === 'darwin' && d.arch === 'x64' && d.format === 'dmg' },
  { key: 'linux', title: 'Linux', detail: 'Ubuntu 24.04 · x64 · .deb', match: d => d.platform === 'linux' },
];

export function downloadPage(brand: Brand | null, release: { version: string; publishedAt: string; downloads: Download[] } | null): string {
  const name = escape(brand?.name ?? '客户端下载');
  const cards = release ? targets.map(t => {
    const file = release.downloads.find(t.match);
    if (!file) return '';
    const base = file.file.split('/').pop()!;
    return `<a class="card" data-target="${t.key}" href="/files/${escape(file.file)}" download="${escape(base)}">
      <span class="os">${t.title}</span><span class="detail">${t.detail}</span>
      <span class="meta">${escape(base)} · ${size(file.bytes)}</span>
      <code title="SHA-256">${file.sha256}</code></a>`;
  }).join('') : '';
  const unsigned = release?.downloads.some(d => !d.signed && d.platform !== 'linux');
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${name} · 下载</title><style>
:root{--bg:#f6f7fb;--fg:#14161f;--muted:#6b7084;--card:#fff;--line:#e3e5ee;--accent:#4f5dff}
@media (prefers-color-scheme:dark){:root{--bg:#0f1117;--fg:#eceef6;--muted:#9aa0b4;--card:#171a23;--line:#262a37;--accent:#7c87ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:880px;margin:0 auto;padding:56px 16px}h1{font-size:30px;margin:0 0 4px}p.sub{color:var(--muted);margin:0 0 32px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.card{display:flex;flex-direction:column;gap:4px;padding:18px;border:1px solid var(--line);border-radius:14px;background:var(--card);color:inherit;text-decoration:none;transition:border-color .15s,transform .15s}
.card:hover{border-color:var(--accent);transform:translateY(-1px)}.card.recommended{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 18%,transparent)}
.os{font-weight:650;font-size:18px}.detail,.meta{color:var(--muted);font-size:13px}code{font-size:11px;color:var(--muted);word-break:break-all;margin-top:6px}
.tag{display:none;align-self:flex-start;font-size:12px;color:var(--accent)}.recommended .tag{display:block}
.notes{margin-top:32px;padding:16px 18px;border-radius:12px;background:var(--card);border:1px solid var(--line);font-size:13px;color:var(--muted)}
.notes code{font-size:12px;color:var(--fg)}
</style></head><body><main>
<h1>${name}</h1>
<p class="sub">${release ? `最新版本 ${escape(release.version)} · 发布于 ${escape(release.publishedAt.slice(0, 10))}` : '暂无可下载的版本。'}</p>
<div class="grid">${cards}</div>
${unsigned ? `<div class="notes"><strong>首次安装提示</strong><br>
Windows：若出现“已保护你的电脑”，点击“更多信息”→“仍要运行”。<br>
macOS：把应用拖入“应用程序”后，如提示“已损坏”或无法验证开发者，在终端执行 <code>xattr -dr com.apple.quarantine "/Applications/应用名.app"</code> 后再打开。<br>
Linux：<code>sudo apt install ./下载的文件.deb</code></div>` : ''}
</main><script>
(()=>{const ua=navigator.userAgent;let k=/Windows/.test(ua)?'windows':/Mac/.test(ua)?'mac':/Linux/.test(ua)&&!/Android/.test(ua)?'linux':'';
const pick=k==='mac'?(navigator.userAgentData?.platform==='macOS'&&navigator.userAgentData.getHighEntropyValues?null:'mac-arm64'):k;
const mark=t=>{const c=document.querySelector('[data-target="'+t+'"]');if(c){c.classList.add('recommended');c.insertAdjacentHTML('afterbegin','<span class="tag">推荐给你的设备</span>')}};
if(pick)mark(pick);else if(k==='mac')navigator.userAgentData.getHighEntropyValues(['architecture']).then(v=>mark(v.architecture==='arm'?'mac-arm64':'mac-x64')).catch(()=>mark('mac-arm64'));})();
</script></body></html>`;
}
