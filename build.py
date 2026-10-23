#!/usr/bin/env python3
"""data/*.json と meta.json から VULNS.md を作り直す。

1件 = data/<ID>.json。毎時のタスクはJSONを追加・更新してから、このスクリプトを実行する。
使い方: python3 build.py
"""
import glob
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
    print(f"VULNS.md を更新しました({len(rows)} 件)")


if __name__ == "__main__":
    main()
