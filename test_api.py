"""API test for unified-auth flow.

本地路径测试为主：预先在 DB 种入用户（pwd_hash + cas_enc），登录走本地校验，
不依赖真实 CAS。错误密码路径会真实访问 CAS，接受 401（密码错误）或 502（网络不可达）。
"""
import hashlib
import json
import sqlite3
import sys
import time
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")
B = "http://localhost:8200"
UID = str(int(time.time()))[-6:]
errs = 0


def api(path, method="GET", data=None, token=None):
    h = {}
    if token:
        h["Authorization"] = "Bearer " + token
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(B + path, data=body, headers=h, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"_raw": raw}
    except Exception as e:
        return 999, {"_error": str(e)}


def check(ok, msg, detail=""):
    global errs
    if ok:
        print(f"  OK {msg}")
    else:
        errs += 1
        d = f": {detail}" if detail else ""
        print(f"  FAIL {msg}{d}")


def seed_user(student_id, password, cas_enc="x"):
    """直接在 DB 中建档，绕过真实 CAS。"""
    conn = sqlite3.connect("data/rollcall.db")
    conn.execute(
        "INSERT OR IGNORE INTO users (student_id, name, pwd_hash, cas_enc, created_at) VALUES (?,?,?,?,?)",
        (student_id, "U" + student_id[-2:], hashlib.sha256(password.encode()).hexdigest(), cas_enc, time.time()),
    )
    conn.commit()
    conn.close()


sid1, sid2 = f"2024{UID}1", f"2024{UID}2"
seed_user(sid1, "p1")
seed_user(sid2, "p2")

# ===== 1. 登录 =====
print("=== Login (本地校验) ===")
s, r = api("/api/login", "POST", {"student_id": sid1, "password": "p1"})
check(s == 200 and "token" in r, "login user A", r)
t1 = r["token"]

s, r = api("/api/login", "POST", {"student_id": sid2, "password": "p2"})
check(s == 200, "login user B", r)
t2 = r["token"]

s, r = api("/api/login", "POST", {"student_id": "nosuchuser999", "password": "x"})
# 未建档用户走 CAS 验证必失败（真实网络），只要求不成功
check(s != 200, f"unknown user rejected (status={s})", r)

s, r = api("/api/register", "POST", {"student_id": sid1, "name": "x", "password": "y"})
# 端点已删：落到鉴权层(401)或路由兜底(404)
check(s in (401, 404), f"register endpoint removed (status={s})", r)

# ===== 2. 用户信息 =====
print("=== User Info ===")
s, r = api("/api/me", "GET", token=t1)
check(s == 200 and r["user"]["cas_bound"] is True, "get me (cas_bound)", r)
check(r["user"]["device_id"] == "", "device_id empty (用组设置)", r)

s, r = api("/api/me", "POST", {"name": "TestA"}, token=t1)
check(s == 200, "update name", r)

# ===== 3. 默认组自动加入 =====
print("=== Default Group ===")
s, r = api("/api/groups", "GET", token=t1)
groups = r.get("groups", [])
default = next((g for g in groups if g["name"] == "默认组"), None)
check(default is not None, "user A auto-joined 默认组", r)
check(default and default.get("device_id") == "86e75964-5563-4a76-9cdb-f26a8dae7ca3",
      "默认组使用站长 device_id", default)

s, r = api("/api/groups", "GET", token=t2)
check(any(g["name"] == "默认组" for g in r.get("groups", [])), "user B auto-joined 默认组", r)

# ===== 4. 建组/加入 =====
print("=== Groups ===")
s, r = api("/api/groups", "POST", {"name": "group1"}, token=t1)
check(s == 200, "create group (无需预绑定)", r)
gid, code = r.get("id"), r.get("invite_code")
check(gid and code, f"group id={gid} code={code}")

s, r = api("/api/groups/join", "POST", {"invite_code": code}, token=t2)
check(s == 200, "join group", r)

s, r = api(f"/api/groups/{gid}/members", "GET", token=t1)
check(s == 200 and len(r["members"]) == 2, "list members", r)

s, r = api(f"/api/groups/{gid}/leave", "POST", token=t2)
check(s == 200, "leave group", r)
s, r = api(f"/api/groups/{gid}/members", "GET", token=t1)
check(s == 200 and len(r["members"]) == 1, "member count after leave", r)
api("/api/groups/join", "POST", {"invite_code": code}, token=t2)

# ===== 5. QR 推送/轮询 =====
print("=== QR Push & Poll ===")
s, r = api(f"/api/groups/{gid}/push", "POST", {
    "rollcall_id": "test123", "data": "qrtestdata", "timestamp": time.time() * 1000}, token=t1)
check(s == 200, "push QR", r)
results = r.get("results", [])
check(len(results) >= 1, f"push returned {len(results)} result(s)", r)
# 成员 B cas_enc 无效 → 优雅失败而非 500
check(any(res.get("status") == "failed" and "重新登录" in res.get("detail", "") for res in results),
      "invalid credential fails gracefully", results)

s, r = api(f"/api/groups/{gid}/poll?since=0", "GET", token=t2)
items = r.get("items", [])
check(s == 200 and len(items) >= 1, f"poll got {len(items)} item(s)", r)
if items:
    check(items[0]["rollcall_id"] == "test123", "QR rollcall_id correct", r)

events = r.get("events", [])
check(len(events) >= 1, f"poll got {len(events)} event(s)", r)
check(any(e["status"] == "scan" for e in events), "scan event recorded", events)
check(any(e["status"] == "failed" and e["target"] != e["scanner"] for e in events),
      "member signin event recorded", events)

s, r = api(f"/api/groups/{gid}/members", "GET", token=t2)
me2 = next((m for m in r["members"] if m["student_id"] == sid2), None)
check(me2 and me2.get("last_signin") == "failed", "member last_signin reflected", me2)

s, r = api(f"/api/groups/{gid}/poll?since={time.time() + 10}", "GET", token=t2)
check(s == 200 and len(r.get("items", [])) == 0, "future poll returns empty", r)

# ===== 6. 错误处理 =====
print("=== Error Handling ===")
s, r = api(f"/api/groups/{gid}/push", "POST", {}, token=t1)
check(s == 400, "push without required fields", r)

s, r = api("/api/groups/join", "POST", {"invite_code": "INVALID"}, token=t1)
check(s == 404, "join invalid code", r)

s, r = api("/api/groups/999999/members", "GET", token=t1)
check(r.get("error") is not None, "nonexistent group rejected", r)

s, r = api("/api/groups/abc/members", "GET", token=t1)
check(s == 404, "invalid group id", r)

s, r = api("/api/me", "GET")
check(s == 401, "no token rejected", r)

# ===== 7. 静态文件 =====
print("=== Static Files ===")
resp = urllib.request.urlopen(f"{B}/", timeout=10)
html = resp.read().decode()
check("签到共享" in html and "统一认证" in html, "index.html served with unified-auth text", html[:80])

print()
if errs:
    print(f"=== {errs} failures ===")
    sys.exit(1)
else:
    print("=== All tests passed! ===")
