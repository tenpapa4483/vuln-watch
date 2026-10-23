# vuln-watch
個人的に脆弱性をまとめるために作成しています。間違いがあることご了承ください。

## 中身
- `VULNS.md`: 脆弱性の一覧表(新しい順)。通常はここを見ます。
- `data/`: 1件につき1ファイルの元データ(JSON)。
- `meta.json`: 最終チェック時刻。
- `build.py`: `data/` と `meta.json` から `VULNS.md` を作り直します(`python3 build.py`)。

毎時のタスクが `data/` に追加・更新して、`VULNS.md` を作り直します。
