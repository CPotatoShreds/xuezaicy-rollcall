#!/usr/bin/env python3
"""
Rollcall Proxy — 学在重邮二维码签到共享工具

完整 Web 应用：用户注册（学号+CAS密码+设备ID）后自动获取 x-session-id，
可创建/加入组，组内一人扫码全员签到。

启动：python server.py
"""
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
import socketserver
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


class ThreadingServer(socketserver.ThreadingMixIn, HTTPServer):
    """并发处理请求的 HTTP 服务器"""
    allow_reuse_address = True
from urllib.parse import urljoin

import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ============ 配置 ============

HTTP_PORT = 8200  # 开发/部署统一对外端口
DB_PATH = str(Path(__file__).parent / "data" / "rollcall.db")
FERNET_KEY_PATH = str(Path(__file__).parent / "data" / "fernet.key")
SESSION_KEEPALIVE_HOURS = 6  # 会话保活扫描周期（见文件末尾 keepalive）
DEFAULT_GROUP_NAME = "默认组"
# 站长设备 ID：默认组成员代签时使用（成员未设置个人 device_id 时）
OWNER_DEVICE_ID = "86e75964-5563-4a76-9cdb-f26a8dae7ca3"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("server")

# ============ Fernet 密钥管理 ============

def _ensure_fernet_key():
    key_dir = Path(FERNET_KEY_PATH).parent
    key_dir.mkdir(parents=True, exist_ok=True)
    if not Path(FERNET_KEY_PATH).exists():
        key = Fernet.generate_key()
        Path(FERNET_KEY_PATH).write_bytes(key)
        log.info("已生成 Fernet 密钥")
    return Path(FERNET_KEY_PATH).read_bytes()

FERNET_KEY = _ensure_fernet_key()
fernet = Fernet(FERNET_KEY)


def encrypt_cas_password(plain: str) -> str:
    return fernet.encrypt(plain.encode()).decode()


def decrypt_cas_password(encrypted: str) -> str:
    try:
        return fernet.decrypt(encrypted.encode()).decode()
    except Exception:
        raise RuntimeError("凭据解密失败，请重新登录以更新")


# ============ 数据库 ============

_local = threading.local()


def get_db():
    if not hasattr(_local, "conn") or _local.conn is None:
        db_dir = Path(DB_PATH).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id  TEXT UNIQUE NOT NULL,
            name        TEXT NOT NULL,
            pwd_hash    TEXT NOT NULL,
            cas_enc     TEXT NOT NULL DEFAULT '',
            cas_cookies TEXT NOT NULL DEFAULT '',
            device_id   TEXT NOT NULL DEFAULT '',
            x_session   TEXT NOT NULL DEFAULT '',
            sess_exp    REAL NOT NULL DEFAULT 0,
            token       TEXT UNIQUE,
            created_at  REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS groups_t (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            invite_code TEXT UNIQUE NOT NULL,
            device_id   TEXT NOT NULL DEFAULT '',
            created_by  INTEGER REFERENCES users(id),
            created_at  REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS group_members (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id  INTEGER NOT NULL REFERENCES groups_t(id),
            user_id   INTEGER NOT NULL REFERENCES users(id),
            role      TEXT NOT NULL DEFAULT 'member',
            joined_at REAL NOT NULL,
            UNIQUE(group_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS qr_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id    INTEGER NOT NULL REFERENCES groups_t(id),
            user_id     INTEGER NOT NULL REFERENCES users(id),
            scanner     TEXT NOT NULL,
            rollcall_id TEXT NOT NULL,
            data        TEXT NOT NULL,
            ts          REAL NOT NULL,
            created_at  REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS signin_events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id  INTEGER NOT NULL REFERENCES groups_t(id),
            scanner   TEXT NOT NULL,
            scanner_id INTEGER NOT NULL,
            target    TEXT NOT NULL,
            target_id INTEGER,
            status    TEXT NOT NULL,
            detail    TEXT NOT NULL DEFAULT '',
            ts        REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_qr_group_ts ON qr_logs(group_id, ts);
        CREATE INDEX IF NOT EXISTS idx_events_group_ts ON signin_events(group_id, ts);
        CREATE INDEX IF NOT EXISTS idx_members_group ON group_members(group_id);
        CREATE INDEX IF NOT EXISTS idx_members_user ON group_members(user_id);
    """)
    conn.commit()
    # 旧库迁移
    for alter in (
        "ALTER TABLE groups_t ADD COLUMN device_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE users ADD COLUMN cas_cookies TEXT NOT NULL DEFAULT ''",
    ):
        try:
            conn.execute(alter)
            conn.commit()
        except sqlite3.OperationalError:
            pass
    _ensure_default_group(conn)


def _ensure_default_group(conn):
    """默认组：所有用户登录后自动加入，使用站长设备 ID 代签。"""
    row = conn.execute("SELECT id FROM groups_t WHERE name=?", (DEFAULT_GROUP_NAME,)).fetchone()
    if row:
        return
    code = _gen_invite_code()
    while conn.execute("SELECT 1 FROM groups_t WHERE invite_code=?", (code,)).fetchone():
        code = _gen_invite_code()
    conn.execute(
        "INSERT INTO groups_t (name, invite_code, device_id, created_by, created_at) VALUES (?,?,?,?,?)",
        (DEFAULT_GROUP_NAME, code, OWNER_DEVICE_ID, None, _now()),
    )
    conn.commit()
    log.info(f"[默认组] 已创建 (邀请码 {code})")


# ============ AES-128-CBC (CQUPT CAS 密码加密) ============

def _random_string(length: int) -> str:
    chars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
    return "".join(chars[ord(os.urandom(1)) % len(chars)] for _ in range(length))


def cas_encrypt_password(password: str, salt: str) -> str:
    key = salt.encode("utf-8")[:16]
    iv = _random_string(16).encode("utf-8")[:16]
    plaintext = (_random_string(64) + password).encode("utf-8")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    block_size = 16
    pad_len = block_size - (len(plaintext) % block_size)
    plaintext += bytes([pad_len] * pad_len)
    encrypted = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()


# ============ CAS 登录客户端 ============

CAS_LOGIN_URL = "https://ids.cqupt.edu.cn/authserver/login"
# 注意：登录不带 service 参数。某些账号（如 1690756）带 service=jwzx 时
# CAS 服务端会在 service 授权阶段抛异常(500)，而我们根本不需要 service 票据，
# 只需要 CASTGC 会话 cookie 触发 LMS 的 Keycloak SSO。
LMS_BASE = "http://lms.tc.cqupt.edu.cn"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")


def _browser_headers(referer: str | None = None) -> dict:
    """贴近真实浏览器请求头。"""
    h = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Upgrade-Insecure-Requests": "1",
    }
    if referer:
        h["Origin"] = "https://ids.cqupt.edu.cn"
        h["Referer"] = referer
    return h


def _extract_login_params(html: str):
    """从登录页提取 execution + 加密盐（pwdEncryptSalt 是真实值，前面可能有同名的空元素）。"""
    exec_m = re.search(r'name="execution" value="([^"]+)"', html)
    salt_m = re.search(r'id="pwdEncryptSalt" value="([^"]+)"', html) or \
        re.search(r'id="(?:pwdDefaultEncryptSalt|encryptSalt)" value="([^"]+)"', html)
    if not exec_m or not salt_m:
        return None, None
    return exec_m.group(1), salt_m.group(1)


def cas_get_x_session_id(student_id: str, password: str) -> tuple[str, str]:
    """完整 CAS 密码登录，返回 (x-session-id, CAS cookies JSON)。

    cookies 用于后续免密码续期（见 x_session_from_cas_cookies）。
    """
    sess = requests.Session()
    sess.headers.update(_browser_headers())

    resp = sess.get(CAS_LOGIN_URL, timeout=15)
    execution, salt = _extract_login_params(resp.text)
    if not execution or not salt:
        raise RuntimeError("CAS 登录页参数提取失败")

    payload = {
        "username": student_id,
        "password": cas_encrypt_password(password, salt),
        "execution": execution,
        "_eventId": "submit",
        "loginType": "1",
        "rememberMe": "true",
    }
    resp = sess.post(CAS_LOGIN_URL, data=payload, timeout=15, headers=_browser_headers(CAS_LOGIN_URL))
    log.info(f"[CAS] {student_id} 提交登录 → HTTP {resp.status_code}")

    # 成功判定：CASTGC 会话 cookie 出现（无 service 时成功不发生 302 跳转）
    has_tgc = any(c.name == "CASTGC" for c in sess.cookies)
    if not has_tgc:
        # 被拒：CAS 可能返回 200/401/500 等多种状态码的错误页，从页面内容判断原因
        msg_m = re.search(r'id="msg"[^>]*>([^<]+)<', resp.text)
        cas_msg = msg_m.group(1).strip() if msg_m else ""
        log.warning(f"[CAS] {student_id} 登录被拒, HTTP {resp.status_code}, 页面提示: {cas_msg or '(无)'}")
        if resp.status_code >= 500:
            body_excerpt = re.sub(r"<script[\s\S]*?</script>|<[^>]+>|\s+", " ", resp.text)[:300]
            log.warning(f"[CAS] 5xx 响应摘要: {body_excerpt}")
        if "密码错误" in resp.text or "密码错误" in cas_msg or "身份认证失败" in resp.text:
            raise RuntimeError("CAS 登录失败：账号或密码错误")
        if cas_msg:
            raise RuntimeError(f"CAS 登录被拒: {cas_msg}")
        raise RuntimeError(f"CAS 登录失败 (HTTP {resp.status_code})，请稍后重试")

    # 若发生了跳转则跟随（一般不会）
    if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
        cur = urljoin(str(resp.url), resp.headers["location"])
        for _ in range(8):
            resp = sess.get(cur, timeout=15)
            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                cur = urljoin(str(resp.url), resp.headers["location"])
                continue
            break

    if not sess.cookies:
        raise RuntimeError("CAS 登录后未获取到 cookie")

    # Step 2: 访问 LMS 首页触发 Keycloak SSO
    resp = sess.get(f"{LMS_BASE}/", timeout=15)
    log.info(f"[CAS] LMS 首页 → {str(resp.url)[:60]} (HTTP {resp.status_code})")
    if "ids.cqupt.edu.cn" in str(resp.url):
        raise RuntimeError("LMS 认证失败，请检查 CAS 会话")

    # Step 3: 调 API 提取 x-session-id
    resp = sess.get(f"{LMS_BASE}/api/todos", timeout=15)
    x_sid = resp.headers.get("x-session-id") or resp.headers.get("X-SESSION-ID")
    if not x_sid:
        raise RuntimeError("未能从 LMS API 响应中提取 x-session-id")
    cookies_json = json.dumps({c.name: c.value for c in sess.cookies})
    return x_sid, cookies_json


def x_session_from_cas_cookies(cookies_json: str) -> str | None:
    """用缓存的 CAS 会话 cookie 免密码续期。

    复用 CASTGC → LMS 首页触发 Keycloak SSO → API 响应头取新 x-session-id。
    cookie 失效或网络异常返回 None（调用方回退到密码登录）。
    """
    if not cookies_json:
        return None
    try:
        cookies = json.loads(cookies_json)
    except (ValueError, TypeError):
        return None
    if not cookies:
        return None
    sess = requests.Session()
    sess.headers.update(_browser_headers())
    sess.cookies.update(cookies)
    try:
        resp = sess.get(f"{LMS_BASE}/", timeout=15)
        if "ids.cqupt.edu.cn" in str(resp.url):
            return None
        resp = sess.get(f"{LMS_BASE}/api/todos", timeout=15)
        return resp.headers.get("x-session-id") or resp.headers.get("X-SESSION-ID")
    except requests.RequestException:
        return None


def renew_session_by_api(old_x_sid: str) -> str | None:
    """滚动续期：带旧 x-session-id 调一次 LMS API，响应头返回新的 x-session-id。

    x-session-id 有效期约 24h 且滚动续期 —— 只要定期使用就永不过期，全程无需 CAS。
    失败返回 None。
    """
    if not old_x_sid:
        return None
    try:
        r = requests.get(f"{LMS_BASE}/api/todos",
                         headers={"User-Agent": UA, "x-session-id": old_x_sid}, timeout=15)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    return r.headers.get("x-session-id") or r.headers.get("X-SESSION-ID") or old_x_sid


def ensure_user_session(conn, u) -> str:
    """确保用户有有效 x-session-id，三级回退：
    1. 旧会话滚动续期（一次 API 调用，最轻量）
    2. CAS cookie 免密码续期
    3. CAS 密码重登（最后手段）
    成功后更新数据库，失败抛 RuntimeError / requests.RequestException。
    u 需含 id, student_id, x_session, cas_cookies, cas_enc 字段。
    """
    # 1. 滚动续期
    x_sid = renew_session_by_api(u["x_session"])
    if x_sid:
        log.info(f"[会话] {u['student_id']} API 续期成功")
    else:
        # 2. CAS cookie 免密码续期
        x_sid = x_session_from_cas_cookies(u["cas_cookies"])
        if x_sid:
            log.info(f"[会话] {u['student_id']} cookie 续期成功")
        else:
            # 3. 密码重登
            pwd = decrypt_cas_password(u["cas_enc"])
            x_sid, cookies_json = cas_get_x_session_id(u["student_id"], pwd)
            conn.execute("UPDATE users SET cas_cookies=? WHERE id=?", (cookies_json, u["id"]))
            log.info(f"[会话] {u['student_id']} 密码重登成功")
    conn.execute("UPDATE users SET x_session=?, sess_exp=? WHERE id=?",
                 (x_sid, _now() + 86400, u["id"]))
    conn.commit()
    return x_sid


# ============ 内部工具 ============

def _hash_pwd(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _gen_token() -> str:
    return secrets.token_urlsafe(32)


def _gen_invite_code() -> str:
    return secrets.token_hex(4).upper()  # 8字符


def _now() -> float:
    return time.time()


def _api_error_detail(resp) -> str:
    """提取 Tronclass 签到接口的可读错误信息（如 签到已结束 / 二维码过期）"""
    try:
        body = resp.json()
    except ValueError:
        text = (resp.text or "").strip()
        return f"HTTP {resp.status_code}: {text[:80]}" if text else f"HTTP {resp.status_code}"
    if isinstance(body, dict):
        for k in ("error", "message", "error_description", "error_msg", "detail", "msg"):
            v = body.get(k)
            if v:
                return f"{str(v)[:100]} (HTTP {resp.status_code})"
    return f"HTTP {resp.status_code}: {str(body)[:80]}"


# ============ HTTP 处理器 ============

class Handler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_OPTIONS(self):
        self._cors_headers()
        self.send_response(204)
        self.end_headers()

    def _route(self):
        method = self.command
        path = urllib.parse.urlparse(self.path).path
        try:
            if path.startswith("/api/"):
                self._handle_api(method, path)
            else:
                super().do_GET()
        except Exception as e:
            log.warning(f"[错误] {method} {path}: {e}")
            self._send(500, {"error": str(e)})

    def _handle_api(self, method: str, path: str):
        # Auth (无需 token)
        if path == "/api/login" and method == "POST":
            return self._login()

        # 以下需要 token
        user_id = self._require_auth()
        if user_id is None:
            return

        if path == "/api/me" and method == "GET":
            return self._get_me(user_id)
        if path == "/api/me" and method == "POST":
            return self._update_me(user_id)
        if path == "/api/refresh-session" and method == "POST":
            return self._refresh_session(user_id)
        if path == "/api/session-status" and method == "GET":
            return self._session_status(user_id)

        # Groups
        if path == "/api/groups" and method == "GET":
            return self._list_groups(user_id)
        if path == "/api/groups" and method == "POST":
            return self._create_group(user_id)
        if path == "/api/groups/join" and method == "POST":
            return self._join_group(user_id)

        # /api/groups/{id}/...
        m = re.match(r"^/api/groups/(\d+)(/.*)?$", path)
        if m:
            gid = int(m.group(1))
            sub = m.group(2) or ""
            if sub == "/members" and method == "GET":
                return self._list_members(user_id, gid)
            if sub == "/push" and method == "POST":
                return self._push_qr(user_id, gid)
            if sub == "/poll" and method == "GET":
                return self._poll_qr(user_id, gid)
            if sub == "/leave" and method == "POST":
                return self._leave_group(user_id, gid)
            if sub == "" and method == "GET":
                return self._group_detail(user_id, gid)

        self._send(404, {"error": "Not Found"})

    # ============ Auth ============

    def _login(self):
        """统一认证登录：登录即建档/绑定 CAS。本地密码校验通过则秒登。"""
        data = self._parse_json()
        student_id = data.get("student_id", "").strip()
        password = data.get("password", "").strip()
        if not student_id or not password:
            return self._send(400, {"error": "统一认证码和密码为必填"})

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE student_id=?", (student_id,)).fetchone()

        if user and user["pwd_hash"] == _hash_pwd(password) and user["cas_enc"]:
            uid = user["id"]
        else:
            # 新用户建档 / 密码变更 / 未绑定 → 走统一认证验证
            try:
                x_sid, cookies_json = cas_get_x_session_id(student_id, password)
            except RuntimeError as e:
                log.warning(f"[统一认证] {student_id} 失败: {e}")
                return self._send(401, {"error": f"统一认证失败: {e}"})
            except requests.RequestException as e:
                log.warning(f"[统一认证] {student_id} 网络异常: {e}")
                return self._send(502, {"error": f"统一认证服务不可达: {e}"})

            cas_enc = encrypt_cas_password(password)
            if user:
                conn.execute(
                    "UPDATE users SET pwd_hash=?, cas_enc=?, cas_cookies=?, x_session=?, sess_exp=? WHERE id=?",
                    (_hash_pwd(password), cas_enc, cookies_json, x_sid, _now() + 86400, user["id"]),
                )
                uid = user["id"]
                log.info(f"[登录] {student_id} 凭据已更新")
            else:
                conn.execute(
                    "INSERT INTO users (student_id, name, pwd_hash, cas_enc, cas_cookies, x_session, sess_exp, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (student_id, student_id, _hash_pwd(password), cas_enc, cookies_json, x_sid, _now() + 86400, _now()),
                )
                uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                log.info(f"[登录] 新用户 {student_id} 建档成功")
            conn.commit()

        # 自动加入默认组
        g = conn.execute("SELECT id FROM groups_t WHERE name=?", (DEFAULT_GROUP_NAME,)).fetchone()
        if g:
            try:
                conn.execute("INSERT INTO group_members (group_id, user_id, role, joined_at) VALUES (?,?,?,?)",
                             (g["id"], uid, "member", _now()))
                conn.commit()
            except sqlite3.IntegrityError:
                pass

        token = _gen_token()
        conn.execute("UPDATE users SET token=? WHERE id=?", (token, uid))
        conn.commit()
        u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return self._send(200, {
            "token": token,
            "user": {
                "id": u["id"],
                "name": u["name"],
                "student_id": u["student_id"],
                "device_id": u["device_id"],
                "cas_bound": bool(u["cas_enc"]),
                "x_session_ok": bool(u["x_session"]) and (u["sess_exp"] > _now()),
            },
        })

    def _require_auth(self) -> int | None:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._send(401, {"error": "未登录"})
            return None
        token = auth[7:]
        conn = get_db()
        user = conn.execute("SELECT id FROM users WHERE token=?", (token,)).fetchone()
        if not user:
            self._send(401, {"error": "登录已过期"})
            return None
        return user["id"]

    # ============ 用户 ============

    def _get_me(self, uid: int):
        conn = get_db()
        u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return self._send(200, {
            "user": {
                "id": u["id"],
                "name": u["name"],
                "student_id": u["student_id"],
                "device_id": u["device_id"],
                "cas_bound": bool(u["cas_enc"]),
                "x_session_ok": bool(u["x_session"]) and (u["sess_exp"] > _now()),
                "x_session_preview": (u["x_session"][:20] + "...") if u["x_session"] else "",
            },
        })

    def _update_me(self, uid: int):
        data = self._parse_json()
        conn = get_db()
        updates = []
        params = []
        if "name" in data:
            updates.append("name=?")
            params.append(data["name"].strip())
        if "device_id" in data:
            updates.append("device_id=?")
            params.append(data["device_id"].strip())
        if updates:
            params.append(uid)
            conn.execute(f"UPDATE users SET {','.join(updates)} WHERE id=?", params)
            conn.commit()
        return self._get_me(uid)

    def _refresh_session(self, uid: int):
        conn = get_db()
        u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not u["cas_enc"]:
            return self._send(400, {"error": "未绑定 CAS 密码"})
        try:
            x_sid = ensure_user_session(conn, u)
            return self._send(200, {"ok": True, "preview": x_sid[:20] + "..."})
        except requests.RequestException as e:
            return self._send(502, {"error": f"统一认证不可达: {e}"})
        except RuntimeError as e:
            return self._send(502, {"error": f"刷新失败: {e}"})

    def _session_status(self, uid: int):
        conn = get_db()
        u = conn.execute("SELECT x_session, sess_exp FROM users WHERE id=?", (uid,)).fetchone()
        return self._send(200, {
            "has_session": bool(u["x_session"]),
            "expires_at": u["sess_exp"],
            "valid": u["sess_exp"] > _now(),
        })

    # ============ 组 ============

    def _list_groups(self, uid: int):
        conn = get_db()
        rows = conn.execute("""
            SELECT g.*, (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as member_count
            FROM groups_t g
            JOIN group_members gm ON gm.group_id=g.id
            WHERE gm.user_id=?
            ORDER BY g.created_at DESC
        """, (uid,)).fetchall()
        return self._send(200, {"groups": [dict(r) for r in rows]})

    def _create_group(self, uid: int):
        data = self._parse_json()
        name = data.get("name", "").strip()
        if not name:
            return self._send(400, {"error": "组名为必填"})
        conn = get_db()
        code = _gen_invite_code()
        while conn.execute("SELECT 1 FROM groups_t WHERE invite_code=?", (code,)).fetchone():
            code = _gen_invite_code()
        conn.execute("INSERT INTO groups_t (name, invite_code, created_by, created_at) VALUES (?,?,?,?)",
                     (name, code, uid, _now()))
        gid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("INSERT INTO group_members (group_id, user_id, role, joined_at) VALUES (?,?,?,?)",
                     (gid, uid, "owner", _now()))
        conn.commit()
        log.info(f"[创建组] {name} ({code}) by {uid}")
        return self._send(200, {"id": gid, "name": name, "invite_code": code, "member_count": 1})

    def _join_group(self, uid: int):
        data = self._parse_json()
        code = data.get("invite_code", "").strip().upper()
        conn = get_db()
        g = conn.execute("SELECT * FROM groups_t WHERE invite_code=?", (code,)).fetchone()
        if not g:
            return self._send(404, {"error": "邀请码无效"})
        try:
            conn.execute("INSERT INTO group_members (group_id, user_id, role, joined_at) VALUES (?,?,?,?)",
                         (g["id"], uid, "member", _now()))
            conn.commit()
            return self._send(200, {"id": g["id"], "name": g["name"]})
        except sqlite3.IntegrityError:
            return self._send(409, {"error": "已在该组中"})

    def _group_detail(self, uid: int, gid: int):
        conn = get_db()
        g = conn.execute("SELECT * FROM groups_t WHERE id=?", (gid,)).fetchone()
        if not g:
            return self._send(404, {"error": "组不存在"})
        if not conn.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", (gid, uid)).fetchone():
            return self._send(403, {"error": "不在该组中"})
        mc = conn.execute("SELECT COUNT(*) FROM group_members WHERE group_id=?", (gid,)).fetchone()[0]
        return self._send(200, {"id": g["id"], "name": g["name"], "invite_code": g["invite_code"], "member_count": mc})

    def _list_members(self, uid: int, gid: int):
        conn = get_db()
        if not conn.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", (gid, uid)).fetchone():
            return self._send(403, {"error": "不在该组中"})
        rows = conn.execute("""
            SELECT u.id, u.name, u.student_id, gm.role, gm.joined_at,
                   u.cas_enc!='' as cas_bound,
                   u.x_session!='' AND u.sess_exp>? as session_valid,
                   (SELECT e.status FROM signin_events e
                     WHERE e.group_id=gm.group_id AND e.target_id=u.id AND e.status IN ('ok','failed')
                     ORDER BY e.ts DESC LIMIT 1) as last_signin,
                   (SELECT e.ts FROM signin_events e
                     WHERE e.group_id=gm.group_id AND e.target_id=u.id AND e.status IN ('ok','failed')
                     ORDER BY e.ts DESC LIMIT 1) as last_signin_ts
            FROM group_members gm JOIN users u ON gm.user_id=u.id
            WHERE gm.group_id=?
            ORDER BY gm.joined_at
        """, (_now(), gid)).fetchall()
        return self._send(200, {"members": [dict(r) for r in rows]})

    def _leave_group(self, uid: int, gid: int):
        conn = get_db()
        conn.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (gid, uid))
        conn.commit()
        return self._send(200, {"ok": True})

    # ============ QR ============

    def _push_qr(self, uid: int, gid: int):
        data = self._parse_json()
        rollcall_id = data.get("rollcall_id", "").strip()
        qr_data = data.get("data", "").strip()
        ts = data.get("timestamp", _now() * 1000) / 1000.0

        if not rollcall_id or not qr_data:
            return self._send(400, {"error": "rollcall_id 和 data 为必填"})

        conn = get_db()
        u = conn.execute("SELECT name, x_session, device_id FROM users WHERE id=?", (uid,)).fetchone()

        # 存储推送
        conn.execute("INSERT INTO qr_logs (group_id, user_id, scanner, rollcall_id, data, ts, created_at) VALUES (?,?,?,?,?,?,?)",
                     (gid, uid, u["name"], rollcall_id, qr_data, ts, _now()))
        conn.commit()
        push_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # 服务器代签：遍历所有组成员（含扫码者本人——网页扫码流程里本人同样没有真实签到）
        g = conn.execute("SELECT device_id FROM groups_t WHERE id=?", (gid,)).fetchone()
        group_dev = (g["device_id"] if g else "") or OWNER_DEVICE_ID
        members = conn.execute("""
            SELECT u.id, u.name, u.x_session, u.device_id, u.cas_enc, u.cas_cookies, u.student_id, u.sess_exp
            FROM group_members gm JOIN users u ON gm.user_id=u.id
            WHERE gm.group_id=? AND u.cas_enc!=''
        """, (gid,)).fetchall()

        results = []
        for m in members:
            x_sid = m["x_session"]
            # 设备优先级：成员个人设置 > 组设置 > 站长设备
            dev_id = m["device_id"] or group_dev

            # 检查 session 是否过期，过期则续期
            if not x_sid or m["sess_exp"] < _now():
                try:
                    x_sid = ensure_user_session(conn, m)
                except RuntimeError as e:
                    results.append({"user_id": m["id"], "name": m["name"], "status": "failed", "detail": f"session刷新失败: {e}"})
                    continue
                except requests.RequestException as e:
                    results.append({"user_id": m["id"], "name": m["name"], "status": "failed", "detail": f"统一认证不可达: {e}"})
                    continue

            # 调签到 API
            try:
                resp = requests.put(
                    f"http://identity.tc.cqupt.edu.cn/api/rollcall/{rollcall_id}/answer_qr_rollcall",
                    headers={
                        "Content-Type": "application/json",
                        "x-session-id": x_sid,
                        "User-Agent": "Mozilla/5.0 (Linux; Android 16; wv) AppleWebKit/537.36",
                        "Origin": "http://mobile.tc.cqupt.edu.cn",
                        "Referer": "http://mobile.tc.cqupt.edu.cn/",
                    },
                    json={"data": qr_data, "deviceId": dev_id},
                    timeout=10,
                )
                if resp.ok:
                    results.append({"user_id": m["id"], "name": m["name"], "status": "ok", "detail": ""})
                else:
                    results.append({"user_id": m["id"], "name": m["name"], "status": "failed", "detail": _api_error_detail(resp)})
            except requests.RequestException as e:
                results.append({"user_id": m["id"], "name": m["name"], "status": "failed", "detail": str(e)[:100]})

        # 记录签到事件（进组历史展示用）
        now = _now()
        events = [(gid, u["name"], uid, u["name"], uid, "scan", "", now)]
        events += [(gid, u["name"], uid, r["name"], r["user_id"], r["status"], r["detail"], now)
                   for r in results]
        conn.executemany(
            "INSERT INTO signin_events (group_id, scanner, scanner_id, target, target_id, status, detail, ts) VALUES (?,?,?,?,?,?,?,?)",
            events,
        )
        conn.commit()

        log.info(f"[推送] {u['name']} → 组{gid} {len(results)}人")
        return self._send(200, {"push_id": push_id, "results": results})

    def _poll_qr(self, uid: int, gid: int):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        try:
            since = float(params.get("since", [0])[0])
        except ValueError:
            since = 0.0

        conn = get_db()
        qr = conn.execute(
            "SELECT id, user_id, scanner, rollcall_id, ts FROM qr_logs WHERE group_id=? AND ts>? ORDER BY ts DESC LIMIT 30",
            (gid, since),
        ).fetchall()
        events = conn.execute(
            "SELECT id, scanner, target, status, detail, ts FROM signin_events WHERE group_id=? AND ts>? ORDER BY ts DESC LIMIT 60",
            (gid, since),
        ).fetchall()
        return self._send(200, {
            "items": [dict(r) for r in qr],
            "events": [dict(e) for e in events],
            "now": _now(),
        })

    # ============ 工具 ============

    def _parse_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        body = self.rfile.read(length)
        return json.loads(body)

    def _send(self, status: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress default HTTP log


# ============ 主入口 ============

# ============ 会话保活 ============

SESSION_KEEPALIVE_HOURS = 6          # 保活扫描周期
SESSION_REFRESH_AHEAD = 12 * 3600    # 距过期不足 12h 则提前刷新（会话有效期 24h）


def _refresh_stale_sessions():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, student_id, x_session, cas_enc, cas_cookies, sess_exp FROM users WHERE cas_enc!=''"
    ).fetchall()
    for u in rows:
        if u["sess_exp"] > _now() + SESSION_REFRESH_AHEAD:
            continue
        try:
            ensure_user_session(conn, u)
        except Exception as e:
            log.warning(f"[保活] {u['student_id']} 刷新失败: {e}")
        time.sleep(5)  # 逐个刷新并间隔，避免触发 CAS 风控


def _keepalive_loop():
    time.sleep(20)  # 启动后先跑一轮，补上停机期间过期的会话
    while True:
        try:
            _refresh_stale_sessions()
        except Exception as e:
            log.warning(f"[保活] 异常: {e}")
        time.sleep(SESSION_KEEPALIVE_HOURS * 3600)


def main():
    init_db()
    threading.Thread(target=_keepalive_loop, daemon=True).start()
    static_dir = Path(__file__).parent / "static"
    os.chdir(str(static_dir))
    server = ThreadingServer(("0.0.0.0", HTTP_PORT), Handler)
    log.info(f"服务启动 → http://localhost:{HTTP_PORT}/")
    log.info("请用手机浏览器打开 http://<本机IP>:%d/" % HTTP_PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("服务已停止")
        server.server_close()


if __name__ == "__main__":
    main()