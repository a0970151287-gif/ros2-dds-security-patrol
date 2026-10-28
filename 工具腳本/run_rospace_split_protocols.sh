#!/usr/bin/env bash
# 下載 ROSPaCe 並跑一次已事前註冊的切分協定量測（C2C-133）。
#
# 在 Jesse 的 WSL（Ubuntu-24.04、使用者 jesse）裡執行。用法：
#
#   cd /mnt/c/Users/Jesse/Documents/專題ROS2
#   git fetch origin claude/dazzling-thompson-qcb75j
#   git show origin/claude/dazzling-thompson-qcb75j:工具腳本/run_rospace_split_protocols.sh > ~/run_rospace.sh
#   bash ~/run_rospace.sh 2>&1 | tee -a ~/run_rospace.log
#
# 這支腳本刻意做成**重跑安全**：
#   * 下載用 `curl -C -` 續傳，md5 對過的檔案會留下標記，不再重下；
#   * 結果檔已存在就只印出它，不重跑（量測工具本身也拒絕覆寫）；
#   * 同時只能有一份在跑（flock）。
#
# 它**不**碰 repo 的工作樹：只 `git fetch` 與 `git show`，工具抽到 $RUN 底下。
# 不啟動 ROS、不產生攻擊流量、不用 sudo、不碰防火牆。
# 判讀（R1–R4、C1）不在這裡做——那由原本的 session 依註冊 dca5ce2 判讀。
set -euo pipefail

REPO=${REPO:-/mnt/c/Users/Jesse/Documents/專題ROS2}
BRANCH=claude/dazzling-thompson-qcb75j
REF="origin/$BRANCH"
PY=${PY:-$HOME/.venvs/sros2-seqmodel/bin/python}
DATA=${DATA:-$HOME/rospace_data}     # 下載的資料（不可信）
RUN=${RUN:-$HOME/rospace_run}        # 工具、清單、結果
OUT="$RUN/ROSPaCe切分協定_result.json"
COLLECTION=6924364                   # springernature.figshare.com 的 ROSPaCe collection（作者 README）
REDUCED_ARTICLE=25594860             # 縮減版（15 個 CSV）
API=${API:-https://api.figshare.com/v2}   # 只有測試會覆寫
MAX_LOAD=${MAX_LOAD:-3}

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
die() { say "⛔ $1"; exit "${2:-1}"; }

mkdir -p "$DATA" "$RUN"
exec 9>"$RUN/.lock"
flock -n 9 || die "已有另一份 run_rospace 在跑（$RUN/.lock）" 3

if [[ -s "$OUT" ]]; then
  say "結果已存在，不重跑：$OUT"
  sha256sum "$OUT"
  cat "$OUT"
  exit 0
fi

# ── 0. 機器要空著 ─────────────────────────────────────────────
say "0. 檢查機器負載"
read -r load1 _ < /proc/loadavg
busy=$(pgrep -af 'firewall_lab\.campaign|run_mega_campaign|gz sim|features\.py' || true)
if [[ -n "$busy" ]]; then
  printf '%s\n' "$busy"
  die "有 campaign 或特徵抽取在跑，不跟它搶" 3
fi
if awk -v l="$load1" -v m="$MAX_LOAD" 'BEGIN{exit !(l>m)}'; then
  die "load $load1 > $MAX_LOAD，機器不空（要強制請設 MAX_LOAD）" 3
fi
free -m || true
df -h "$DATA" | tail -1 || true

# ── 1. 取工具（不碰工作樹） ─────────────────────────────────────
say "1. 從 $REF 取工具、測試、註冊"
export GIT_TERMINAL_PROMPT=0   # 沒有認證就直接失敗，不要卡在等密碼
GIT=(git -c "safe.directory=$REPO" -C "$REPO")
if ! "${GIT[@]}" fetch origin "$BRANCH" 2>"$RUN/git_fetch.err"; then
  say "⚠️ WSL 裡的 git fetch 失敗（多半是沒有 GitHub 認證）："
  cat "$RUN/git_fetch.err"
  say "   若 Windows 那邊已經 fetch 過，就沿用本機的 $REF"
fi
"${GIT[@]}" rev-parse --verify --quiet "$REF" >/dev/null \
  || die "找不到 $REF。請在 PowerShell 跑：git -C C:\\Users\\Jesse\\Documents\\專題ROS2 fetch origin $BRANCH，然後重跑這支" 2
TOOL_COMMIT=$("${GIT[@]}" rev-parse "$REF")
mkdir -p "$RUN/工具腳本" "$RUN/tests" "$RUN/文件"
"${GIT[@]}" show "$REF:工具腳本/rospace_split_protocols.py" > "$RUN/工具腳本/rospace_split_protocols.py"
"${GIT[@]}" show "$REF:tests/test_rospace_split_protocols.py" > "$RUN/tests/test_rospace_split_protocols.py"
"${GIT[@]}" show "$REF:文件/預測_ROSPaCe的切分協定_2026-10-23.md" > "$RUN/文件/預測_ROSPaCe的切分協定_2026-10-23.md"
say "   工具來自 commit $TOOL_COMMIT"

[[ -x "$PY" ]] || die "找不到 $PY" 2
"$PY" -I - > "$RUN/versions.txt" <<'PYEOF'
import importlib, platform, sys
print("python", platform.python_version())
for name in ("numpy", "pandas", "sklearn", "scipy", "xgboost", "pytest"):
    try:
        print(name, importlib.import_module(name).__version__)
    except Exception as exc:  # noqa: BLE001
        print(name, "MISSING", type(exc).__name__)
PYEOF
cat "$RUN/versions.txt"
grep -q '^xgboost MISSING' "$RUN/versions.txt" && die "venv 沒有 xgboost（不要 pip install 進這個 venv，回報即可）" 2

if grep -q '^pytest MISSING' "$RUN/versions.txt"; then
  say "   ⚠️ venv 沒有 pytest，略過測試（雲端容器已以相同 numpy/pandas/sklearn/scipy 跑過 24 passed）"
  echo "skipped: pytest missing" > "$RUN/tests_result.txt"
else
  say "   跑 24 個測試"
  if ! (cd "$RUN" && "$PY" -m pytest -q -p no:cacheprovider tests/test_rospace_split_protocols.py) \
        > "$RUN/tests_result.txt" 2>&1; then
    tail -30 "$RUN/tests_result.txt"
    die "測試沒全過，停" 4
  fi
  tail -3 "$RUN/tests_result.txt"
fi

# ── 2. 列出 figshare 檔案 ─────────────────────────────────────
say "2. 向 figshare 列出 collection $COLLECTION 的檔案"
python3 -I - "$API" "$COLLECTION" "$REDUCED_ARTICLE" "$RUN/figshare_files.json" <<'PYEOF'
import json, sys, urllib.request

api, collection, reduced_article, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "rospace-split-protocols/1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

articles = get(f"{api}/collections/{collection}/articles?page_size=100")
listing = []
for a in articles:
    files = get(f"{api}/articles/{a['id']}/files?page_size=1000")
    listing.append({"article_id": a["id"], "title": a.get("title"),
                    "files": [{k: f.get(k) for k in ("id", "name", "size", "computed_md5", "download_url")}
                              for f in files]})
json.dump(listing, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
for a in listing:
    total = sum(f["size"] or 0 for f in a["files"])
    print(f"article {a['article_id']}  {len(a['files'])} files  {total/1e9:.2f} GB  {a['title']}")
    for f in a["files"]:
        print(f"    {f['name']}  {(f['size'] or 0)/1e9:.3f} GB  md5 {f['computed_md5']}")

complete = [(a["article_id"], f) for a in listing for f in a["files"]
            if f["name"].lower().startswith("complete_dataset")]
if len(complete) != 1:
    sys.exit(f"⛔ 找到 {len(complete)} 個 complete_dataset* 檔，預期剛好 1 個；不猜，停")
reduced = sorted((f for a in listing if a["article_id"] == reduced_article for f in a["files"]
                  if f["name"].lower().endswith((".csv", ".zip"))), key=lambda f: f["name"])
if not reduced:
    sys.exit(f"⛔ article {reduced_article} 不在 collection 裡或沒有 CSV；不猜，停")
pick = {"complete": complete[0][1], "reduced_one": reduced[0]}
json.dump(pick, open(out.replace(".json", "_pick.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
print("選定：", pick["complete"]["name"], "＋", pick["reduced_one"]["name"])
PYEOF
PICK="$RUN/figshare_files_pick.json"

field() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]][sys.argv[3]])' "$PICK" "$1" "$2"; }

need=$(python3 -I -c 'import json,sys; p=json.load(open(sys.argv[1])); c=p["complete"]["size"]; r=p["reduced_one"]["size"]; z=2 if p["complete"]["name"].lower().endswith(".zip") else 1; print(c*z+r+10*10**9)' "$PICK")
avail=$(df --output=avail -B1 "$DATA" | tail -1)
(( avail > need )) || die "磁碟不夠：需要 $((need/10**9)) GB、只剩 $((avail/10**9)) GB" 2

# ── 3. 下載（續傳 ＋ md5） ─────────────────────────────────────
fetch() {  # $1 = complete | reduced_one
  # 中斷 ≠ 壞檔：curl 沒有下完就保留已下的部分、下一輪續傳；
  # 只有「大小已經對了而 md5 不對」才刪掉重下（40 GB 從頭來的代價很高）。
  local name url md5 size dest attempt bad=0 have rc got
  name=$(field "$1" name); url=$(field "$1" download_url)
  md5=$(field "$1" computed_md5); size=$(field "$1" size)
  dest="$DATA/$name"
  if [[ -z "$md5" || "$md5" == None ]]; then
    die "figshare 沒有提供 $name 的 md5；不在無法驗證的情況下下載 40 GB，停" 5
  fi
  if [[ -f "$dest.md5ok" && "$(cat "$dest.md5ok")" == "$md5" ]]; then
    say "   $name 已下載且 md5 相符，略過"
    return 0
  fi
  for attempt in $(seq 1 20); do
    have=$(stat -c %s "$dest" 2>/dev/null || echo 0)
    if (( have < size )); then
      say "   下載 $name（第 $attempt 輪，已有 $((have/10**6)) / $((size/10**6)) MB）"
      rc=0
      curl -L --fail --retry 5 --retry-delay 10 -C - -o "$dest" "$url" || rc=$?
      have=$(stat -c %s "$dest" 2>/dev/null || echo 0)
      if (( have < size )); then
        say "   ⚠️ curl 中斷（rc=$rc），保留已下的部分，30 秒後續傳"
        sleep 30
        continue
      fi
    fi
    if (( have > size )); then
      say "   ⚠️ 檔案比 figshare 宣稱的大（$have > $size），刪掉重下"
      rm -f "$dest"; bad=$((bad+1))
    else
      got=$(md5sum "$dest" | cut -d' ' -f1)
      if [[ "$got" == "$md5" ]]; then
        echo "$md5" > "$dest.md5ok"
        say "   $name md5 相符 $md5"
        return 0
      fi
      say "   ⚠️ 大小對但 md5 不符（得到 $got、預期 $md5），刪掉重下"
      rm -f "$dest"; bad=$((bad+1))
    fi
    (( bad < 3 )) || die "$name 三次下載完整卻 md5 都不符，停" 5
  done
  die "$name 下載 20 輪仍未完成（網路一直中斷），停；重跑這支會從斷點續傳" 5
}
say "3. 下載到 $DATA"
fetch reduced_one
fetch complete

unpack() {  # 若是 zip 就解到子目錄；印出 CSV 路徑
  local f="$DATA/$1" d
  if [[ "$f" == *.zip ]]; then
    command -v unzip >/dev/null || die "需要 unzip（sudo apt install unzip——這一步請 Jesse 自己決定）" 2
    d="${f%.zip}_unzipped"
    if [[ ! -f "$d/.done" ]]; then
      mkdir -p "$d"
      unzip -o -q "$f" -d "$d" >&2
      touch "$d/.done"
    fi
    find "$d" -type f -name '*.csv' | sort
  else
    printf '%s\n' "$f"
  fi
}
mapfile -t COMPLETE_CSVS < <(unpack "$(field complete name)")
REDUCED_CSV=$(unpack "$(field reduced_one name)" | head -1 || true)
(( ${#COMPLETE_CSVS[@]} > 0 )) || die "完整版裡沒有 CSV" 5
[[ -n "$REDUCED_CSV" ]] || die "縮減版裡沒有 CSV" 5

for f in "${COMPLETE_CSVS[@]}"; do
  hdr=$(head -c 1000000 "$f" | head -1 || true)   # head 提早關管線會讓 pipefail 誤判
  python3 -I -c 'import csv,sys; h=next(csv.reader([sys.argv[1]])); m=[c for c in ("timestamp","attack") if c not in h]; sys.exit(f"⛔ {sys.argv[2]} 缺欄位 {m}" if m else 0); ' "$hdr" "$f"
done
say "   完整版 CSV：${COMPLETE_CSVS[*]}"
say "   縮減版表頭來源：$REDUCED_CSV"

# ── 4. 量測 ────────────────────────────────────────────────────
say "4. 執行量測（預估 1.5–2 小時）"
start=$(date +%s)
cmd=("$PY" -I "$RUN/工具腳本/rospace_split_protocols.py"
     --csv "${COMPLETE_CSVS[@]}" --feature-columns-from "$REDUCED_CSV" --output "$OUT")
if [[ -x /usr/bin/time ]]; then
  /usr/bin/time -v -o "$RUN/time.txt" "${cmd[@]}" || rc=$?
else
  "${cmd[@]}" || rc=$?
  echo "(no /usr/bin/time)" > "$RUN/time.txt"
fi
rc=${rc:-0}
echo "wall_sec $(( $(date +%s) - start ))" >> "$RUN/time.txt"
[[ $rc -eq 0 ]] || die "量測工具以 rc=$rc 結束（原樣回報，不要修工具）" 6

# ── 5. 回報 ────────────────────────────────────────────────────
say "5. 完成"
{
  echo "tool_commit $TOOL_COMMIT"
  cat "$RUN/versions.txt"
  echo "tests: $(tail -1 "$RUN/tests_result.txt")"
  grep -E 'Elapsed|Maximum resident|wall_sec' "$RUN/time.txt" || true
  sha256sum "$OUT"
} | tee "$RUN/SUMMARY.txt"
cat "$OUT"
