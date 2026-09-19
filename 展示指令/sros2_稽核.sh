#!/usr/bin/env bash
# ============================================================================
# sros2_稽核.sh — SROS2 加固姿態離線稽核（唯讀，不改任何東西）
#
# 在 Metasploit 滲透測試前跑這支，確認「牆」結構正確：
#   G1 雙 CA 分離 / G2 最小權限 / 金鑰權限 / governance 強度 / 憑證鏈 / 到期
# 全綠才代表加密結構健全，再做 live Enforce 煙霧測試。
#
# 用法： bash 展示指令/sros2_稽核.sh
# ============================================================================
set -uo pipefail
WS="$HOME/ros2_ws"
KS="$WS/sros2_keystore"
POL="$WS/展示指令/sros2_policy_least_privilege.xml"
PASS=0; FAIL=0; WARN=0
ok(){ echo "  ✅ $1"; PASS=$((PASS+1)); }
no(){ echo "  ❌ $1"; FAIL=$((FAIL+1)); }
wn(){ echo "  ⚠️  $1"; WARN=$((WARN+1)); }
EXPECTED_ENCLAVES=(
  burger_env_top dds_security_monitor gazebo intelligent_defense_node
  listener mission_manager patrol_node sensor_hub_node system_status_node
  talker velocity_guard_node security_readiness_probe local_outcome_probe
)

echo "════════ SROS2 加固稽核 ════════"
[[ -d "$KS" ]] || { echo "❌ 找不到 keystore：$KS（先跑 10_SROS2啟用.sh）"; exit 1; }
[[ -f "$POL" ]] || { echo "❌ 找不到 canonical policy：$POL"; exit 1; }

echo "── Enclave inventory ──"
actual_enclaves="$(
  find "$KS/enclaves" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' |
    sort
)"
expected_enclaves="$(printf '%s\n' "${EXPECTED_ENCLAVES[@]}" | sort)"
if [[ "$actual_enclaves" == "$expected_enclaves" ]]; then
  ok "enclave inventory 與 canonical 清單完全一致"
else
  no "enclave inventory 不一致（缺少或多出 enclave）"
  diff -u <(printf '%s\n' "$expected_enclaves") \
          <(printf '%s\n' "$actual_enclaves") || true
fi

echo "── G1：identity CA 與 permissions CA 是否分離 ──"
ic=$(readlink -f "$KS/public/identity_ca.cert.pem" 2>/dev/null)
pc=$(readlink -f "$KS/public/permissions_ca.cert.pem" 2>/dev/null)
ich=$(sha256sum "$ic" 2>/dev/null | cut -c1-16); pch=$(sha256sum "$pc" 2>/dev/null | cut -c1-16)
if [[ "$ich" != "$pch" ]]; then ok "雙 CA 已分離（identity=$ich, permissions=$pch）"
else no "identity 與 permissions 共用同一把 CA（G1 未加固，跑 10_SROS2啟用.sh 重建）"; fi

echo "── 金鑰權限（私鑰不可被 group/other 讀）──"
# 只看真實檔（-type f 排除 symlink；symlink 自身權限恆 777 會誤判）
bad=$(find "$KS" -type f \( -name "*.key.pem" -o -name "key.pem" \) | while read -r f; do
  p=$(stat -c '%a' "$f"); [[ "$p" =~ ^[0-7]00$ ]] || echo "$f($p)"; done)
[[ -z "$bad" ]] && ok "所有私鑰真檔權限 ≤ 600" || no "私鑰權限過鬆：$bad"

echo "── G2：最小權限（政策不得含 wildcard topic）──"
w=$(grep -Ec "<(topic|service|action)>[^<]*\*" "$POL" 2>/dev/null || true)
[[ "${w:-0}" == "0" ]] && ok "政策 0 個 wildcard topic/service/action" || no "政策仍有 $w 個 wildcard"
# 同時檢查實際簽進 keystore 的 permissions 有沒有殘留 wildcard
gw=$(grep -El "<(topic|service|action)>[^<]*\*" "$KS"/enclaves/*/permissions.xml 2>/dev/null | wc -l)
[[ "$gw" == "0" ]] && ok "keystore 內 permissions 無 wildcard" || no "$gw 個 enclave 的 permissions 仍含 wildcard"

echo "── keystore 與 canonical 政策一致性（防過時簽章）──"
# 「signed permissions == permissions.xml」只證明 keystore 內部自洽；
# keystore 整份過時時仍會全綠。2026-08-03 政策新增 velocity_guard_node 的
# security/heartbeat 訂閱但 keystore 未重簽，Enforce 於執行期才拒絕並拖垮
# 整組節點，當時稽核卻仍報 47/47。這一項逐節點比對實際授權集合。
DRIFT_CHECKER="$WS/工具腳本/check_keystore_policy_drift.py"
if [[ -f "$DRIFT_CHECKER" ]]; then
  drift_out="$(python3 "$DRIFT_CHECKER" --keystore "$KS" --policy "$POL" 2>&1)"
  if grep -q "^DRIFT=0$" <<<"$drift_out"; then
    ok "keystore 授權集合與 canonical 政策一致（無過時簽章）"
  else
    no "keystore 落後 canonical 政策（需重跑 create_permission）"
    grep -v "^DRIFT=" <<<"$drift_out" | sed 's/^/     /'
  fi
else
  wn "找不到漂移檢查器：$DRIFT_CHECKER"
fi

echo "── governance 強度 ──"
G="$KS/enclaves/governance.xml"
GP7S="$KS/enclaves/governance.p7s"
chk(){ grep -q "$1" "$G" && ok "$2" || no "$2（缺 $1）"; }
chk "<allow_unauthenticated_participants>false" "禁止未認證 participant"
chk "<enable_join_access_control>true" "啟用 join 存取控制"
grep -qE "rtps_protection_kind>(SIGN|ENCRYPT)" "$G" && ok "RTPS 保護(SIGN/ENCRYPT) → 擋偽造 RTPS" || no "RTPS 無保護"
grep -qE "discovery_protection_kind>ENCRYPT" "$G" && ok "discovery 加密 → 擋竊聽列舉" || wn "discovery 未加密"
dom=$(grep -oE "<id>[0-9]+</id>" "$G" | head -1 | grep -oE "[0-9]+")
expected_domain="${ROS_DOMAIN_ID:-30}"
[[ "$dom" == "$expected_domain" ]] \
  && ok "governance domain=$dom 與 ROS_DOMAIN_ID 一致" \
  || no "governance domain=${dom:-?}，預期 $expected_domain"
openssl smime -verify -in "$GP7S" -inform SMIME \
  -CAfile "$KS/public/permissions_ca.cert.pem" -out /dev/null \
  >/dev/null 2>&1 \
  && ok "signed governance 由 permissions CA 驗證通過" \
  || no "signed governance 驗證失敗"

echo "── 憑證鏈 + 到期 ──"
now=$(date +%s)
for cert in "$KS"/enclaves/*/cert.pem; do
  [[ -f "$cert" ]] || continue
  en=$(basename "$(dirname "$cert")")
  # 身分鏈：cert 應由 identity_ca 簽
  if openssl verify -CAfile "$KS/public/identity_ca.cert.pem" "$cert" >/dev/null 2>&1; then
    chainok=1; else chainok=0; fi
  # 到期
  end=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
  ends=$(date -d "$end" +%s 2>/dev/null || echo 0)
  days=$(( (ends - now) / 86400 ))
  if [[ "$chainok" == 1 && "$days" -gt 30 ]]; then ok "$en：身分鏈 OK，憑證剩 ${days}d"
  elif [[ "$chainok" != 1 ]]; then no "$en：身分憑證鏈驗證失敗（不是 identity_ca 簽的？）"
  else wn "$en：憑證將於 ${days}d 內到期，宜輪替"; fi
  # 權限簽章：permissions.p7s 應可被 permissions_ca 驗證
  pp="$(dirname "$cert")/permissions.p7s"
  px="$(dirname "$cert")/permissions.xml"
  if [[ -f "$pp" ]]; then
    extracted="$(mktemp)"
    if openssl smime -verify -text -in "$pp" -inform SMIME \
      -CAfile "$KS/public/permissions_ca.cert.pem" \
      -out "$extracted" >/dev/null 2>&1; then
      ok "$en：權限簽章由 permissions_ca 驗證通過"
      # OpenSSL S/MIME -text 會把已簽內容輸出成 CRLF；只正規化換行，
      # 其餘 bytes 仍須與目前 permissions.xml 完全相同。
      sed 's/\r$//' "$extracted" > "$extracted.normalized"
      cmp -s "$extracted.normalized" "$px" \
        && ok "$en：signed permissions 內容等於 permissions.xml" \
        || no "$en：signed permissions 與 permissions.xml 不一致"
    else
      no "$en：權限簽章驗不過（permissions_ca 不符 → Enforce 會擋自己）"
    fi
    rm -f "$extracted" "$extracted.normalized"
  else
    no "$en：缺少 permissions.p7s"
  fi
done

echo "════════════════════════════════"
echo "結果： ✅ $PASS   ⚠️ $WARN   ❌ $FAIL"
[[ "$FAIL" == 0 ]] && echo "→ 加固結構健全，可做 live Enforce 煙霧測試後讓紅隊 Metasploit 開打。" \
                   || echo "→ 有 ❌，先修（多半重跑 10_SROS2啟用.sh）再測。"
(( FAIL == 0 )) || exit 1
