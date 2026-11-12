#!/usr/bin/env python3
"""data/*.json と meta.json から VULNS.md を作り直す。

1件 = data/<ID>.json。毎時のタスクはJSONを追加・更新してから、このスクリプトを実行する。
使い方: python3 build.py
"""
import glob
import html
import json
import os
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
JST = timezone(timedelta(hours=9))


def parse(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def jst(ts):
    d = parse(ts)
    return d.astimezone(JST).strftime("%m/%d %H:%M") if d else ""


def cell(text):
    """表のセルに入れる文字列から、表を壊す文字を取り除く。"""
    return str(text or "").replace("\r", " ").replace("\n", " ").replace("|", "\\|").strip()


def link_title(text):
    return cell(text).replace("[", "(").replace("]", ")")


def level(score):
    if not isinstance(score, (int, float)):
        return "未評価"
    if score >= 9:
        return "緊急"
    if score >= 7:
        return "高"
    if score >= 4:
        return "中"
    return "低"


def load_rows():
    rows = []
    for path in glob.glob(os.path.join(ROOT, "data", "*.json")):
        with open(path, encoding="utf-8") as f:
            row = json.load(f)
        row["_id"] = os.path.splitext(os.path.basename(path))[0]
        rows.append(row)
    rows.sort(key=lambda r: (r.get("detectedAt") or "", r["_id"]), reverse=True)
    return rows


def render_row(r):
    score = r.get("cvss")
    if isinstance(score, (int, float)):
        ver = r.get("cvssVersion")
        cvss = f"{score:.1f} ({level(score)})" + (f"<br>v{cell(ver)}" if ver else "")
    else:
        cvss = "未評価"

    if r.get("exploited") == "confirmed":
        exp = "**悪用確認あり**"
        if r.get("exploitNote"):
            exp += "<br>" + cell(r["exploitNote"])
    else:
        exp = "確認されていない"

    links = []
    for s in r.get("sources") or []:
        url = (s or {}).get("url", "")
        if url.startswith("http://") or url.startswith("https://"):
            links.append(f"[{link_title(s.get('title') or url)}]({url.replace(' ', '%20').replace(')', '%29')})")

    ident = cell(r.get("cve") or r["_id"])
    return "| " + " | ".join([
        jst(r.get("detectedAt")),
        f"**{ident}**<br>{cell(r.get('product'))}",
        cell(r.get("summary")),
        cvss,
        exp,
        "<br>".join(links),
    ]) + " |"


CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#e2e2e2;--card:#fafafa;--red:#b42318;--redbg:#fee4e2;--amb:#b54708;--ambbg:#fef0c7;--acc:#175cd3}
@media(prefers-color-scheme:dark){:root{--bg:#141414;--fg:#eee;--mut:#9a9a9a;--line:#333;--card:#1c1c1c;--red:#fda29b;--redbg:#55160c;--amb:#fec84b;--ambbg:#4e2e09;--acc:#84adff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,"Hiragino Sans","Yu Gothic",sans-serif}
main{max-width:920px;margin:0 auto;padding:16px}h1{margin:.2em 0;font-size:1.5em}
.note{color:var(--mut);font-size:.9em}.stats{color:var(--mut);margin:.5em 0 1em}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
input[type=search]{flex:1;min-width:180px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:16px}
label{display:flex;align-items:center;gap:6px}
.card{border:1px solid var(--line);background:var(--card);border-radius:10px;padding:12px 14px;margin-bottom:10px}
.head{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}.id{font-weight:700}
.prod{color:var(--mut);font-size:.92em}.badges{margin:6px 0;display:flex;gap:6px;flex-wrap:wrap}
.b{font-size:.8em;padding:2px 8px;border-radius:999px;border:1px solid var(--line)}
.b.exp{background:var(--redbg);color:var(--red);border-color:transparent;font-weight:700}
.b.hi{background:var(--ambbg);color:var(--amb);border-color:transparent}
.src a{color:var(--acc);margin-right:10px;font-size:.9em;word-break:break-all}
.time{color:var(--mut);font-size:.85em;white-space:nowrap}
"""

JS = """
const q=document.getElementById('q'),ex=document.getElementById('ex'),cards=[...document.querySelectorAll('.card')],cnt=document.getElementById('cnt');
function f(){const t=q.value.toLowerCase();let n=0;cards.forEach(c=>{const ok=c.textContent.toLowerCase().includes(t)&&(!ex.checked||c.dataset.exp==='1');c.hidden=!ok;if(ok)n++});cnt.textContent=n}
q.addEventListener('input',f);ex.addEventListener('change',f);f();
"""


def render_card(r):
    e = html.escape
    score = r.get("cvss")
    badges = []
    if r.get("exploited") == "confirmed":
        note = r.get("exploitNote")
        badges.append(f'<span class="b exp">悪用確認あり{(" · " + e(str(note))) if note else ""}</span>')
    if isinstance(score, (int, float)):
        ver = r.get("cvssVersion")
        cls = "b hi" if score >= 9 else "b"
        badges.append(f'<span class="{cls}">CVSS {score:.1f} ({level(score)}){(" v" + e(str(ver))) if ver else ""}</span>')
    else:
        badges.append('<span class="b">CVSS 未評価</span>')
    links = []
    for s in r.get("sources") or []:
        url = (s or {}).get("url", "")
        if url.startswith("http://") or url.startswith("https://"):
            links.append(f'<a href="{e(url, quote=True)}" target="_blank" rel="noopener noreferrer">{e(str(s.get("title") or url))}</a>')
    ident = e(str(r.get("cve") or r["_id"]))
    return (
        f'<article class="card" data-exp="{1 if r.get("exploited") == "confirmed" else 0}">'
        f'<div class="head"><span class="id">{ident}</span><span class="time">{e(jst(r.get("detectedAt")))}</span></div>'
        f'<div class="prod">{e(str(r.get("product") or ""))}</div>'
        f'<div class="badges">{"".join(badges)}</div>'
        f'<div>{e(str(r.get("summary") or ""))}</div>'
        f'<div class="src">{"".join(links)}</div></article>'
    )


def render_html(rows, checked, exploited):
    cards = "\n".join(render_card(r) for r in rows)
    return f"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>脆弱性ウォッチ</title><style>{CSS}</style></head><body><main>
<h1>脆弱性ウォッチ</h1>
<p class="note">自動収集のため、内容に誤りがある可能性があります。対応の前に、必ず各項目のソース(一次情報)を確認してください。</p>
<p class="stats">最終チェック: {html.escape(checked)}(日本時間) / 登録 {len(rows)} 件 / 悪用確認あり {exploited} 件 / 表示 <span id="cnt"></span> 件</p>
<div class="bar"><input id="q" type="search" placeholder="CVE番号・製品名・キーワードで絞り込み"><label><input id="ex" type="checkbox">悪用確認ありのみ</label></div>
{cards}
</main><script>{JS}</script></body></html>
"""


def main():
    rows = load_rows()
    meta = {}
    meta_path = os.path.join(ROOT, "meta.json")
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)

    exploited = sum(1 for r in rows if r.get("exploited") == "confirmed")
    checked = jst(meta.get("lastCheckedAt")) or "未実行"

    out = [
        "# 脆弱性ウォッチ",
        "",
        "> 自動収集のため、内容に誤りがある可能性があります。対応の前に、必ず各行のソース(一次情報)を確認してください。",
        "",
        f"- 最終チェック: {checked}(日本時間)",
        f"- 登録: {len(rows)} 件 / 悪用確認あり: {exploited} 件",
        "- 新しい順に並んでいます。",
        "",
        "| 検知(JST) | ID・製品 | 要約 | CVSS | 悪用状況 | ソース |",
        "|---|---|---|---|---|---|",
    ]
    out += [render_row(r) for r in rows]
    out.append("")

    with open(os.path.join(ROOT, "VULNS.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    with open(os.path.join(ROOT, "index.html"), "w", encoding="utf-8") as f:
        f.write(render_html(rows, checked, exploited))
    print(f"VULNS.md を更新しました({len(rows)} 件)")


if __name__ == "__main__":
    main()
