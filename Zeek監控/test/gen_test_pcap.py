#!/usr/bin/env python3
"""產生合成 pcap 驗證 dds_monitor.zeek 三類規則 + 白名單(FPR)。
純標準函式庫，無 scapy 依賴。模擬 domain-30 RTPS UDP 流量。

封包設計：
  1) 正常(白名單)  10.10.10.2 -> 239.255.0.1:14900   應「不」告警(FPR=0)
  2) 偵察          10.10.10.1 -> 239.255.0.1:14900   觸發 [偵察攻擊]
  3) 注入          10.10.10.1 -> 10.10.10.2:14913    payload 含 INJECTED → [注入攻擊]
  4) DoS           10.10.10.1:(多來源埠) -> 239.255.0.1:14900 x30 → [DoS 攻擊]
"""
import struct, socket, sys

def ipv4_checksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return (~s) & 0xFFFF

def eth(dst, src):
    return dst + src + b"\x08\x00"

def ipv4(src_ip, dst_ip, payload_len, proto=17):
    ver_ihl = 0x45
    tos = 0
    total = 20 + payload_len
    ident = 0
    flags_frag = 0
    ttl = 64
    chk = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ident,
                      flags_frag, ttl, proto, chk, src, dst)
    chk = ipv4_checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ident,
                       flags_frag, ttl, proto, chk, src, dst)

def udp(sport, dport, payload):
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload

def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))

MAC_A = mac("02:00:00:00:00:01")        # 攻擊機 10.10.10.1（任意 MAC）
MAC_T = mac("34:5a:60:96:c3:ca")        # 目標機 10.10.10.2 真實 eth0 MAC（白名單綁定）
MAC_MC = mac("01:00:5e:7f:00:01")       # 239.255.0.1 多播

def frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload):
    u = udp(sport, dport, payload)
    ip = ipv4(src_ip, dst_ip, len(u))
    return eth(dst_mac, src_mac) + ip + u

pkts = []  # (ts_float, bytes)
RTPS = b"RTPS\x02\x03" + b"\x00" * 20   # 假 RTPS 標頭

# 1) 正常白名單探索（FPR 測試，不應告警）
pkts.append((0.0, frame(MAC_T, MAC_MC, "10.10.10.2", "239.255.0.1", 14900, 14900, RTPS)))
# 2) 偵察：攻擊機新 participant 上線
pkts.append((1.0, frame(MAC_A, MAC_MC, "10.10.10.1", "239.255.0.1", 14910, 14900, RTPS)))
# 3) 注入：攻擊機送帶簽章的 DATA 到資料埠
inj = b"RTPS\x02\x03" + b"\x00" * 8 + b"[INJECTED] forged cmd_vel"
pkts.append((2.0, frame(MAC_A, MAC_T, "10.10.10.1", "10.10.10.2", 14913, 14913, inj)))
# 4) DoS：8 秒內 30 個偽造 participant 灌 SPDP
for i in range(30):
    pkts.append((3.0 + i * 0.1, frame(MAC_A, MAC_MC, "10.10.10.1", "239.255.0.1",
                                      40000 + i, 14900, RTPS)))
# 5) F1 參數竄改：攻擊機呼叫 set_parameters 服務
param = b"RTPS\x02\x03" + b"\x00" * 8 + b"rq/listener/set_parametersRequest use_sim_time"
pkts.append((7.0, frame(MAC_A, MAC_T, "10.10.10.1", "10.10.10.2", 14913, 14913, param)))
# 6) F7 來源 IP 偽造：宣稱 IP=10.10.10.2(信任) 但用攻擊者 MAC → 應抓到
pkts.append((8.0, frame(MAC_A, MAC_MC, "10.10.10.2", "239.255.0.1", 14910, 14900, RTPS)))

out = sys.argv[1] if len(sys.argv) > 1 else "/home/jesse/ros2_ws/Zeek監控/test/dds_attack_test.pcap"
with open(out, "wb") as f:
    # pcap global header: magic, ver 2.4, zone, sig, snaplen, linktype=1(Eth)
    f.write(struct.pack("!IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, data in pkts:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        f.write(struct.pack("!IIII", sec, usec, len(data), len(data)))
        f.write(data)
print(f"寫出 {out}：{len(pkts)} 個封包")
