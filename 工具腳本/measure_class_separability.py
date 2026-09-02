"""同樣的問題，但用**正確的**資料：三個重跑過的類別取自 dataset_rerun300。

`dataset_live` 是 300 場受控重跑**之前**的資料，而 replay／parameter_tamper／
service_dos 正是那次修好的三類（C2C-024）。拿舊資料量它們，會重現一個已知
且已修的缺陷，並把它報成現況。
"""
import collections, json, pathlib, sys

LIVE = pathlib.Path("/home/jesse/ros2_ws/firewall_lab/dataset_live")
RERUN = pathlib.Path("/home/jesse/dataset_rerun300")
MODE = sys.argv[1] if len(sys.argv) > 1 else "permissive"
# C2C-024：這三個 scenario 於 2026-08-21 按相同 seed／mode 受控重跑並在特徵層替換。
RERUN_SCENARIOS = {"heartbeat_replay", "parameter_tamper", "parameter_flood"}

def signals(path):
    c = collections.Counter()
    f = path / "telemetry_events.jsonl"
    if not f.is_file():
        return c
    with f.open(encoding="utf-8") as fh:
        for line in fh:
            try: e = json.loads(line)
            except ValueError: continue
            kind = e.get("event_type")
            if not kind: continue
            c[kind] += 1
            d = e.get("details")
            if not isinstance(d, dict): continue
            toks = []
            for k, v in d.items():
                if isinstance(v, bool): toks.append("%s=%s" % (k, v))
                elif isinstance(v, (int, float)): toks.append(k + (">0" if v else "=0"))
                elif isinstance(v, str) and v: toks.append("%s=%s" % (k, v))
            for t in toks: c["%s.%s" % (kind, t)] += 1
            for i in range(len(toks)):
                for j in range(i + 1, len(toks)):
                    c["%s.%s&%s" % (kind, toks[i], toks[j])] += 1
    return c

by_class = collections.defaultdict(collections.Counter)
n = collections.Counter()
src = collections.defaultdict(set)
for root in (RERUN, LIVE):                       # 重跑優先
    if not root.is_dir():
        continue
    for man in sorted(root.glob("*/manifest.json")):
        m = json.loads(man.read_text(encoding="utf-8"))
        if m.get("security_mode") != MODE or m.get("status") != "complete":
            continue
        sc, cls = m.get("scenario_id"), m["attack_class"]
        # 重跑過的 scenario 只採用重跑版
        if root is LIVE and sc in RERUN_SCENARIOS:
            continue
        if n[cls] >= 12:
            continue
        by_class[cls] += signals(man.parent)
        n[cls] += 1
        src[cls].add(root.name)

print("=== %s：取樣來源 ===" % MODE)
for k in sorted(n):
    print("  %-20s %2d 場   %s" % (k, n[k], ",".join(sorted(src[k]))))

normal = set(by_class.get("normal", collections.Counter()))
excl = {k: set(v) - normal for k, v in by_class.items() if k != "normal"}
print()
names = sorted(excl)
bad = []
for i in range(len(names)):
    for j in range(i + 1, len(names)):
        a, b = names[i], names[j]
        ua, ub = excl[a] - excl[b], excl[b] - excl[a]
        if not (ua and ub):
            bad.append((a, b, len(ua), len(ub)))
print("=== 不可分的組合：%d / %d ===" % (len(bad), len(names)*(len(names)-1)//2))
for a, b, ua, ub in bad:
    print("  ⛔ %-20s ←→ %-20s  a獨有 %d  b獨有 %d" % (a, b, ua, ub))
if not bad:
    print("  ✅ 九類兩兩全部可分")
