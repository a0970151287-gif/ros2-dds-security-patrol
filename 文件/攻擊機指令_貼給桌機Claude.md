# 貼給桌機 Claude 的完整指示

> Jesse：把**這條分隔線以下的全部內容**複製給 5080 桌機上的 Claude。
> 它是自足的——那台機器沒有這個 repo，所以攻擊腳本也一起帶過去了。

---

你負責**攻擊端**。防守端在另一台筆電上，由另一個 Claude 負責。這是一個
ROS 2 / DDS 資安專題的跨主機實驗，目的是取得「認證失敗」的 DDS 層證據。

## 〇、先讀這條界線

**這台機器絕對不可以有防守方的 SROS2 keystore、私鑰或 enclave。**

不要向 Jesse 索取、不要複製 `sros2_keystore/`、不要複製任何 `key.pem`。
攻擊機上有防守方私鑰，整個威脅模型就沒有意義了——那不是「外部攻擊者」，
是「已經被完全攻陷的內部主機」。

下面的攻擊腳本**自己生一個 CA、自己簽憑證**，不需要防守方的任何檔案。

**另外：在 Jesse 對該次操作明確說「可以執行」之前，不要跑攻擊。**
這個專案的規則是每一次 live 操作單獨授權，不因前一次已授權而延續。
你可以先把環境全部建好、驗證好，然後停下來等他點頭。

## 一、要達成什麼

一句話：**讓這台機器跑一個 DDS participant，它的憑證由錯誤的 CA 簽發，
而且它有一個與防守機同網段、但不同的 IP。**

為什麼 IP 必須不同：防守方要證明「這個 IP 上只有一個 participant，而且它不是
合法身分，所以封鎖它不會波及別人」。同一台機器上做不到——所有 participant
共用同一批位址，這是物理限制不是設定問題。整個跨主機實驗就是為了解決這一點。

## 二、要裝什麼

只有兩樣：

- **ROS 2 Jazzy**，要有 `demo_nodes_cpp`（`ros2 run demo_nodes_cpp talker` 能跑）
- **openssl**

不需要 Gazebo、不需要專案原始碼、不需要 Python 機器學習環境。

## 三、網路（比軟體重要，先做這個）

這台必須有一個**與防守機同網段的 IPv4**，而且兩邊能互相 ping。

| 作法 | 侵入性 | 說明 |
|---|---|---|
| **Linux VM ＋ bridged 網路** | **最低，建議** | 不動桌機的 Windows，VM 直接拿一個區網 IP |
| WSL2 ＋ `networkingMode=mirrored` | 低 | 比 VM 輕；防守端就是用這個 |
| 雙開 Linux | 高 | 最乾淨但最麻煩 |

⚠️ **預設 NAT 模式的 WSL2 不行。** 位址會像 `172.30.x.x`，防守機連不到，
DDS 的多播也穿不過 NAT。

檢查（兩台都做，前三段要一樣）：

```bash
ip addr        # Linux / WSL
```

```bash
ipconfig       # Windows
```

然後互 ping。**ping 不通就不要往下走**——常見原因是一邊 WiFi 一邊有線被路由
隔開，或路由器開了 AP isolation。

## 四、⚠️ 一個會讓整輪白跑的坑（防守端 2026-08-26 踩過）

如果 `libfastrtps` 與 `libfastcdr` 解析到**不同目錄**，DDS 的 discovery 會
**靜默失效**：participant 建得起來、安全外掛照樣載入、log 乾乾淨淨、程式跑滿
整個視窗，但兩邊完全看不見對方。

防守端就是因為這個，觀測者連續兩次「什麼都沒記到」，被誤判成時序問題查了很久。

**跑之前先確認一次：**

```bash
source /opt/ros/jazzy/setup.bash && ldd /opt/ros/jazzy/lib/libfastrtps.so.2.14 | grep fastcdr
```

`libfastcdr` 必須解析到 `/opt/ros/jazzy/lib/`。若指向 `/usr/local/lib/`，
表示這台裝過另一套 Fast DDS，請先確認有 source 到 ROS 的 `setup.bash`。

**這一點特別重要**，因為它的失敗形態是「攻擊看起來成功執行了、但防守端什麼都
沒收到」——會被誤讀成「防禦擋住了」或「防禦沒反應」，兩個結論都是錯的。

## 五、建立攻擊腳本

把下面的內容存成 `N28_wrong_ca_participant.sh`（放哪都可以，例如 `~/`）：

```bash
#!/usr/bin/env bash
# 攻擊 N28 — wrong-CA secure participant：進入 SROS2 握手然後認證失敗
#
# 為什麼需要這個攻擊：
#   既有的 unauthorized_participant 用的是「完全沒有安全設定」的 participant。
#   它不會進入 SROS2 的安全握手，因此防守方沒有任何「認證失敗」可以記錄。
#   它不是被拒絕，是從一開始就不在那個協定裡。
#
#   N28 相反：攻擊者**有**一張看起來完整的身分憑證，只是由**別的 CA** 簽的。
#   它會發起握手，防守方用自己的 identity_ca 驗證憑證鏈 → 驗不過 → 拒絕。
set -u

DURATION="${1:-40}"
DOMAIN="${ROS_DOMAIN_ID:-30}"
REAL_KEYSTORE="${SROS2_REAL_KEYSTORE:-$HOME/ros2_ws/sros2_keystore}"
W="${SROS2_WRONGCA_DIR:-$HOME/.local/share/sros2-firewall/wrongca}"
NODE_CN="/wrong_ca_intruder"

echo "=================================================================="
echo " N28  wrong-CA secure participant → authentication denial"
echo "=================================================================="
echo "  domain    : $DOMAIN"
echo "  duration  : ${DURATION}s"
echo "  workspace : $W"

# 跨主機時攻擊機**不該**有防守方的 keystore。這裡只用它的 public CA 憑證做
# 對照顯示，所以缺了就跳過顯示，不要中止：攻擊本身自己生 CA。
HAVE_REAL_KEYSTORE=1
if [ ! -d "$REAL_KEYSTORE/public" ]; then
  HAVE_REAL_KEYSTORE=0
  echo "ℹ️  找不到防守方 keystore（$REAL_KEYSTORE）。"
  echo "    跨主機時這是正常的——攻擊機不該持有防守方的檔案。"
  echo "    僅略過 CA 對照顯示，攻擊照常執行。"
fi

command -v ros2 >/dev/null 2>&1 || {
  echo "❌ 找不到 ros2。請先 source /opt/ros/jazzy/setup.bash" >&2
  exit 3
}
command -v openssl >/dev/null 2>&1 || { echo "❌ 找不到 openssl" >&2; exit 3; }

rm -rf "$W"; mkdir -p "$W/enclaves/$NODE_CN" "$W/public" "$W/private"
cd "$W" || exit 1

echo
echo "[1/4] 生成攻擊者自己的 CA（與防守方無任何關係）"
printf '[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=v3\n[dn]\nCN=wrongCA\n[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ca.cnf
openssl ecparam -name prime256v1 -genkey -noout -out private/ca.key.pem 2>/dev/null
openssl req -new -x509 -key private/ca.key.pem -out public/ca.cert.pem \
  -days 30 -config ca.cnf 2>/dev/null
cp public/ca.cert.pem public/identity_ca.cert.pem
cp public/ca.cert.pem public/permissions_ca.cert.pem
echo "      CA subject: $(openssl x509 -in public/ca.cert.pem -noout -subject 2>/dev/null)"
if [ "$HAVE_REAL_KEYSTORE" -eq 1 ]; then
  echo "      防守方 CA : $(openssl x509 -in "$REAL_KEYSTORE/public/identity_ca.cert.pem" -noout -subject 2>/dev/null)"
else
  echo "      防守方 CA : （攻擊機無此檔，跨主機時屬正常）"
fi
echo "      → 兩者不同，憑證鏈驗證必定失敗，這正是本攻擊要觸發的路徑"

echo
echo "[2/4] 用攻擊者 CA 簽出身分憑證 CN=$NODE_CN"
E="enclaves/$NODE_CN"
printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=%s\n' "$NODE_CN" > node.cnf
openssl ecparam -name prime256v1 -genkey -noout -out "$E/key.pem" 2>/dev/null
openssl req -new -key "$E/key.pem" -out node.csr -config node.cnf 2>/dev/null
openssl x509 -req -in node.csr -CA public/ca.cert.pem -CAkey private/ca.key.pem \
  -CAcreateserial -out "$E/cert.pem" -days 30 2>/dev/null
cp public/identity_ca.cert.pem    "$E/identity_ca.cert.pem"
cp public/permissions_ca.cert.pem "$E/permissions_ca.cert.pem"

echo
echo "[3/4] 產生並簽署 governance / permissions"
cat > governance.xml <<XML
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <domain_access_rules>
    <domain_rule>
      <domains><id>$DOMAIN</id></domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <liveliness_protection_kind>ENCRYPT</liveliness_protection_kind>
      <rtps_protection_kind>SIGN</rtps_protection_kind>
      <topic_access_rules>
        <topic_rule>
          <topic_expression>*</topic_expression>
          <enable_discovery_protection>true</enable_discovery_protection>
          <enable_liveliness_protection>true</enable_liveliness_protection>
          <enable_read_access_control>true</enable_read_access_control>
          <enable_write_access_control>true</enable_write_access_control>
          <metadata_protection_kind>ENCRYPT</metadata_protection_kind>
          <data_protection_kind>ENCRYPT</data_protection_kind>
        </topic_rule>
      </topic_access_rules>
    </domain_rule>
  </domain_access_rules>
</dds>
XML
cat > permissions.xml <<XML
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <permissions>
    <grant name="intruder">
      <subject_name>CN=$NODE_CN</subject_name>
      <validity>
        <not_before>2026-01-01T00:00:00</not_before>
        <not_after>2027-12-31T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains><id>$DOMAIN</id></domains>
        <publish><topics><topic>*</topic></topics></publish>
        <subscribe><topics><topic>*</topic></topics></subscribe>
      </allow_rule>
      <default>DENY</default>
    </grant>
  </permissions>
</dds>
XML
for f in governance permissions; do
  # 必須是 S/MIME multipart，不是 PEM 包的 PKCS7。-outform PEM 會產生
  # -----BEGIN PKCS7-----，Fast DDS 回 "Input data has not PKCS7 S/MIME
  # format" 並拒絕啟動。
  openssl smime -sign -in "$f.xml" -text -nodetach \
    -signer public/ca.cert.pem -inkey private/ca.key.pem \
    -out "$E/$f.p7s" 2>/dev/null
done
cp permissions.xml "$E/permissions.xml"
echo "      enclave: $(ls "$E" | tr '\n' ' ')"

echo
echo "[4/4] 以 wrong-CA 身分加入 domain $DOMAIN（Enforce），持續 ${DURATION}s"
export ROS_SECURITY_KEYSTORE="$W"
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_ENCLAVE_OVERRIDE="$NODE_CN"
export ROS_DOMAIN_ID="$DOMAIN"
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export PYTHONUNBUFFERED=1

# 不要用管線接 tail：$? 會變成 tail 的狀態，讓失敗看起來像成功。
ATTACK_LOG="$W/attack_output.log"
timeout --signal=TERM "$DURATION" ros2 run demo_nodes_cpp talker --ros-args --enclave "$NODE_CN" >"$ATTACK_LOG" 2>&1
rc=$?
tail -20 "$ATTACK_LOG"

if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
  echo "❌ participant 未能啟動（rc=$rc）——沒有握手，不可視為攻擊已執行。" >&2
fi
if grep -qE "Traceback|command not found|No such file" "$ATTACK_LOG" 2>/dev/null; then
  echo "❌ 攻擊行程崩潰，見 $ATTACK_LOG" >&2
  rc=1
fi

echo
echo "=================================================================="
echo " 結束（rc=$rc）。攻擊者產物保留在 $W 供稽核。"
echo "=================================================================="
```

## 六、乾跑一次（**不會**產生跨主機攻擊流量，可以現在做）

在等 Jesse 授權之前，先確認腳本本身能跑完。用一個**沒有人在用的 domain**，
例如 77，這樣不會碰到防守機：

```bash
source /opt/ros/jazzy/setup.bash && ROS_DOMAIN_ID=77 bash ~/N28_wrong_ca_participant.sh 15
```

看到 `Publishing: 'Hello World: N'` 就表示 participant 起得來、憑證產得出來。
`rc=124` 是**正常**的（timeout 到期）。

## 七、正式執行（**需要 Jesse 當次明確授權**）

與防守端協調時序：**先確認防守方的觀測者已啟動，再跑 N28。**

```bash
source /opt/ros/jazzy/setup.bash && export ROS_DOMAIN_ID=30 && bash ~/N28_wrong_ca_participant.sh 40
```

`ROS_DOMAIN_ID` 必須與防守方相同（30）。

### 怎麼確認真的執行了

`rc=124`（或 0）＋ attack log 裡有 `Publishing: 'Hello World: N'`。

**如果 rc 是其他非零值，participant 根本沒起來，不可以回報成「攻擊已執行」。**
這個專案已經被「攻擊回報成功但其實沒執行」咬過三次，所以一定要看 log 確認。

## 八、要回報什麼

| 項目 | 用途 |
|---|---|
| 這台機器的**實際 IPv4** | 對照防守方擷取到的來源 IP |
| N28 的 rc 與 attack log 的 Publishing 行數 | 證明攻擊真的執行了 |
| 攻擊**開始／結束的 UTC 時間** | 對齊防守方的觀測視窗 |
| `ldd` 那項檢查的結果 | 排除靜默失效 |

取得 UTC 時間：

```bash
date -u +%Y-%m-%dT%H:%M:%SZ
```

**不要**回傳 `wrongca/private/ca.key.pem`——雖然那是攻擊者自己生的、沒有價值，
但保持「私鑰不離開產生它的機器」這個習慣。

## 九、你不該做的事

- 不要複製或索取防守方的 keystore、私鑰、enclave
- 不要在這台執行 `sudo` 的防火牆操作（nftables 是防守端的事）
- 不要修改防守端的任何檔案
- 不要把攻擊流量發到約定的 domain 以外的地方
- **不要在未取得 Jesse 對該次操作的明確授權前執行正式攻擊**
