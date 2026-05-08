"""
SecOps Automation Dashboard — Local Edition
현재 PC(Linux/Windows/macOS)를 직접 모니터링하고 보호합니다.

보안 설계 원칙:
  - subprocess 는 항상 인자 리스트(shell=False) 로 호출 — 셸 인젝션 방지
  - 방화벽 명령 실행 전 IP/도메인 정규식 검증 필수
  - 모든 차단/해제 작업에 사용자 명시적 승인 필요
  - 이 앱을 0.0.0.0 으로 바인딩할 경우 신뢰 네트워크 내에서만 사용하십시오
"""

import io
import os
import re
import sys
import socket
import platform
import subprocess
import logging
from datetime import datetime
from typing import Optional

import streamlit as st

try:
    import qrcode
    from PIL import Image
    _QR_AVAILABLE = True
except ImportError:
    _QR_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secops-local")

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
_OS = platform.system()          # "Windows" | "Linux" | "Darwin"
IS_WINDOWS = _OS == "Windows"
IS_LINUX   = _OS == "Linux"
IS_MAC     = _OS == "Darwin"

# ---------------------------------------------------------------------------
# Mobile CSS
# ---------------------------------------------------------------------------
_CSS = """
<style>
.stButton > button { min-height: 44px; font-size: 15px; border-radius: 8px; }
@media (max-width: 640px) {
    .stButton > button { width: 100%; }
    div[data-testid="column"] { width: 100% !important; flex: 100% !important; }
}
.info-card {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.15);
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 10px;
}
</style>
"""

# ---------------------------------------------------------------------------
# Regex validators
# ---------------------------------------------------------------------------
_IP_RE     = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$")
# IPs that must never be blocked
_PROTECTED = ("127.", "0.0.0.0", "::1")

_PHISHING_KEYWORDS = [
    "긴급", "확인", "계정", "정지", "클릭", "비밀번호", "로그인", "보안",
    "업데이트", "당첨", "무료", "이벤트", "인증", "보상", "탈취",
    "urgent", "verify", "account", "suspended", "click here", "limited time",
    "confirm your", "password", "login", "security alert", "update required",
    "unusual activity", "prize", "winner", "free gift",
]
_SUSPICIOUS_URL_RE = [
    re.compile(r"http://(?!\S+\.(?:gov|edu|mil|or\.kr))\S+", re.I),
    re.compile(r"\d{1,3}(?:\.\d{1,3}){3}", re.I),
    re.compile(r"(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd)/\S+", re.I),
]


# ---------------------------------------------------------------------------
# subprocess helper — shell=False 강제
# ---------------------------------------------------------------------------
def _run_local(args: list[str], timeout: int = 20) -> dict:
    """
    로컬 명령어를 인자 리스트로 실행한다. shell=False 고정.
    반환: {"stdout", "stderr", "exit_code", "permission_denied"}
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,          # 셸 인젝션 차단
        )
        perm_denied = (
            result.returncode in (1, 2) and
            any(kw in result.stderr.lower()
                for kw in ("permission denied", "access denied",
                           "operation not permitted", "must be root",
                           "administrator"))
        )
        return {
            "stdout":           result.stdout,
            "stderr":           result.stderr,
            "exit_code":        result.returncode,
            "permission_denied": perm_denied,
        }
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"명령어를 찾을 수 없습니다: {args[0]}",
                "exit_code": -1, "permission_denied": False}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "명령어 실행 시간 초과",
                "exit_code": -1, "permission_denied": False}
    except Exception as exc:
        return {"stdout": "", "stderr": str(exc),
                "exit_code": -1, "permission_denied": False}


def _check_perm(result: dict) -> bool:
    """권한 오류 발생 시 UI 안내 후 True 반환."""
    if result["permission_denied"]:
        if IS_WINDOWS:
            st.error(
                "🔒 **권한 부족** — 관리자 권한이 필요합니다.\n\n"
                "PowerShell 또는 CMD를 **관리자 권한으로 실행**한 후 앱을 다시 시작하십시오."
            )
        else:
            st.error(
                "🔒 **권한 부족** — root 또는 sudo 권한이 필요합니다.\n\n"
                "`sudo streamlit run app.py` 로 앱을 다시 실행하십시오."
            )
        return True
    return False


# ---------------------------------------------------------------------------
# DNS resolution — IPv4 only
# ---------------------------------------------------------------------------
def resolve_target(target: str) -> tuple[str, list[str]]:
    target = target.strip()
    if _IP_RE.match(target):
        return "ip", [target]
    if _DOMAIN_RE.match(target):
        try:
            infos = socket.getaddrinfo(target, None)
            ips = list(dict.fromkeys(
                i[4][0] for i in infos if i[0] == socket.AF_INET
            ))
            return "domain", ips
        except socket.gaierror:
            return "domain", []
    return "invalid", []


# ---------------------------------------------------------------------------
# Risk Analysis
# ---------------------------------------------------------------------------
def analyze_text(text: str) -> dict:
    text_lower = text.lower()
    score, findings = 0, []

    matched = [kw for kw in _PHISHING_KEYWORDS if kw in text_lower]
    if matched:
        score += len(matched) * 10
        findings.append(f"의심 키워드: `{', '.join(matched)}`")

    for pattern in _SUSPICIOUS_URL_RE:
        hits = pattern.findall(text)
        if hits:
            score += 20
            findings.append(f"의심 URL 패턴: `{hits[0]}`")

    if len(text) < 120 and score > 0:
        score += 15
        findings.append("짧은 긴급 메시지 (스미싱 전형 패턴)")

    score = min(score, 100)
    if score >= 60:
        badge = "🔴 HIGH"
    elif score >= 30:
        badge = "🟡 MEDIUM"
    else:
        badge = "🟢 LOW"

    return {"score": score, "badge": badge, "findings": findings,
            "timestamp": datetime.now().isoformat(timespec="seconds")}


# ---------------------------------------------------------------------------
# PC Security Info — read-only queries
# ---------------------------------------------------------------------------
def get_network_connections() -> str:
    """현재 PC의 네트워크 연결 상태 (ESTABLISHED 위주)."""
    if IS_WINDOWS:
        r = _run_local(["netstat", "-ano"])
    else:
        r = _run_local(["ss", "-tnp", "state", "established"])
        if r["exit_code"] != 0:               # fallback to netstat
            r = _run_local(["netstat", "-tnp"])
    return r["stdout"] or r["stderr"] or "(연결 없음)"


def get_listening_ports() -> str:
    """현재 PC에서 LISTEN 중인 포트 목록."""
    if IS_WINDOWS:
        r = _run_local(["netstat", "-ano", "-p", "TCP"])
    else:
        r = _run_local(["ss", "-tlnp"])
        if r["exit_code"] != 0:
            r = _run_local(["netstat", "-tlnp"])
    return r["stdout"] or r["stderr"] or "(정보 없음)"


def get_process_list() -> str:
    """실행 중인 프로세스 목록."""
    if IS_WINDOWS:
        r = _run_local(["tasklist", "/fo", "table"])
    else:
        r = _run_local(["ps", "aux", "--sort=-%cpu"])
    return r["stdout"] or r["stderr"] or "(정보 없음)"


def get_firewall_rules() -> str:
    """현재 방화벽 규칙 조회."""
    if IS_WINDOWS:
        r = _run_local([
            "netsh", "advfirewall", "firewall", "show", "rule",
            "name=all", "dir=in", "type=dynamic",
        ])
        if r["exit_code"] != 0:
            r = _run_local([
                "netsh", "advfirewall", "firewall", "show", "rule", "name=BlockIP*",
            ])
    else:
        r = _run_local(["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"])
        if r["exit_code"] != 0:
            r = _run_local(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
    if _check_perm(r):
        return ""
    return r["stdout"] or r["stderr"] or "(규칙 없음)"


# ---------------------------------------------------------------------------
# Firewall — block
# ---------------------------------------------------------------------------
def block_ips(ips: list[str]) -> str:
    protected = [ip for ip in ips if any(ip.startswith(p) for p in _PROTECTED)]
    if protected:
        return f"⚠️ 보호된 주소 포함 — 차단 거부됨: {protected}"

    lines = []
    for ip in ips:
        if not _IP_RE.match(ip):
            lines.append(f"[SKIP] IPv4 아님: {ip}")
            continue

        if IS_WINDOWS:
            # netsh advfirewall — 인자 리스트, shell=False
            for direction, dir_flag in [("inbound", "in"), ("outbound", "out")]:
                r = _run_local([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=SecOps_Block_{ip}_{direction}",
                    f"dir={dir_flag}",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                ])
                lines.append(f"[netsh add {dir_flag}] {ip}")
                if r["stdout"].strip():
                    lines.append(r["stdout"].strip())
                if r["stderr"].strip():
                    lines.append(f"[stderr] {r['stderr'].strip()}")
                lines.append(f"exit: {r['exit_code']}")
                if _check_perm(r):
                    return "\n".join(lines)
        else:
            for args in [
                ["sudo", "iptables", "-I", "INPUT",  "-s", ip, "-j", "DROP"],
                ["sudo", "iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
            ]:
                r = _run_local(args)
                lines.append(f"$ {' '.join(args)}")
                if r["stderr"].strip():
                    lines.append(f"[stderr] {r['stderr'].strip()}")
                lines.append(f"exit: {r['exit_code']}")
                if _check_perm(r):
                    return "\n".join(lines)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Firewall — unblock
# ---------------------------------------------------------------------------
def unblock_target_local(target: str) -> tuple[str, list[str], str]:
    kind, ips = resolve_target(target)
    if kind == "invalid":
        return kind, [], "⚠️ 유효한 주소를 입력하세요."
    if kind == "domain" and not ips:
        return kind, [], f"⚠️ 도메인 `{target}` DNS 조회 실패"

    lines = []
    for ip in ips:
        if IS_WINDOWS:
            for direction in ["inbound", "outbound"]:
                r = _run_local([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=SecOps_Block_{ip}_{direction}",
                ])
                lines.append(f"[netsh delete {direction}] {ip}")
                if r["stdout"].strip():
                    lines.append(r["stdout"].strip())
                if r["stderr"].strip():
                    lines.append(f"[stderr] {r['stderr'].strip()}")
                lines.append(f"exit: {r['exit_code']}")
        else:
            for args in [
                ["sudo", "iptables", "-D", "INPUT",  "-s", ip, "-j", "DROP"],
                ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            ]:
                r = _run_local(args)
                lines.append(f"$ {' '.join(args)}")
                if r["stderr"].strip():
                    lines.append(f"[stderr] {r['stderr'].strip()}")
                lines.append(f"exit: {r['exit_code']}")

    return kind, ips, "\n".join(lines)


# ---------------------------------------------------------------------------
# Firewall — flush
# ---------------------------------------------------------------------------
def flush_firewall() -> str:
    lines = []
    if IS_WINDOWS:
        r = _run_local([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            "name=SecOps_Block*",
        ])
        lines.append("[netsh delete SecOps_Block* rules]")
        lines.append(r["stdout"] or r["stderr"])
        lines.append(f"exit: {r['exit_code']}")
        if _check_perm(r):
            return "\n".join(lines)
    else:
        for args in [
            ["sudo", "iptables", "-F", "INPUT"],
            ["sudo", "iptables", "-F", "OUTPUT"],
        ]:
            r = _run_local(args)
            lines.append(f"$ {' '.join(args)}")
            if r["stderr"].strip():
                lines.append(f"[stderr] {r['stderr'].strip()}")
            lines.append(f"exit: {r['exit_code']}")
            if _check_perm(r):
                return "\n".join(lines)
    return "\n".join(lines)


# ===========================================================================
# WireGuard VPN helpers
# ===========================================================================

# Windows WireGuard 기본 경로
_WG_WIN_DIR  = r"C:\Program Files\WireGuard"
_WG_WIN_EXE  = os.path.join(_WG_WIN_DIR, "wireguard.exe")
_WG_WIN_TOOL = os.path.join(_WG_WIN_DIR, "wg.exe")
# Windows 기본 터널 설정 저장 위치
_WG_WIN_CONF_DIR = r"C:\ProgramData\WireGuard"


def check_admin_windows() -> bool:
    """Windows 관리자 권한 여부 확인."""
    if not IS_WINDOWS:
        return True   # Linux/Mac 은 별도 sudo 체크
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _wg_exe() -> str:
    """실행 가능한 wireguard.exe / wg.exe 경로 반환. PATH 우선."""
    # PATH 에 있으면 우선 사용
    r = _run_local(["wg", "--version"])
    if r["exit_code"] == 0:
        return "wg"
    # Windows 기본 설치 경로
    if IS_WINDOWS and os.path.isfile(_WG_WIN_TOOL):
        return _WG_WIN_TOOL
    return "wg"


def _wg_installed() -> bool:
    """WireGuard 설치 여부 확인 (Windows/Linux 공용)."""
    if IS_WINDOWS:
        return os.path.isfile(_WG_WIN_EXE) or _run_local(["wg", "--version"])["exit_code"] == 0
    return _run_local(["wg", "--version"])["exit_code"] == 0


def wg_status(interface: str = "wg0") -> dict:
    """인터페이스 상태: installed / running / admin_ok."""
    installed = _wg_installed()
    admin_ok  = check_admin_windows() if IS_WINDOWS else True

    if not installed:
        return {"installed": False, "running": False,
                "admin_ok": admin_ok, "output": ""}

    if IS_WINDOWS:
        r = _run_local(["sc", "query", f"WireGuardTunnel${interface}"])
        running = "RUNNING" in r["stdout"]
    else:
        r = _run_local(["sudo", "wg", "show", interface])
        running = r["exit_code"] == 0 and bool(r["stdout"].strip())

    return {"installed": True, "running": running,
            "admin_ok": admin_ok, "output": r["stdout"] or r["stderr"]}


def create_server_config(
    interface: str = "wg0",
    server_address: str = "10.0.0.1/24",
    listen_port: int = 51820,
) -> dict:
    """
    서버용 키 쌍 생성 + wg0.conf 작성.
    Windows: C:\\ProgramData\\WireGuard\\<interface>.conf
    Linux:   /etc/wireguard/<interface>.conf
    반환: {"priv", "pub", "conf_path", "conf_text", "error"}
    """
    wg_bin = _wg_exe()
    priv_r = _run_local([wg_bin, "genkey"])
    if priv_r["exit_code"] != 0 or not priv_r["stdout"].strip():
        return {"error": f"키 생성 실패: {priv_r['stderr']}"}

    priv = priv_r["stdout"].strip()
    try:
        pub_proc = subprocess.run(
            [wg_bin, "pubkey"], input=priv,
            capture_output=True, text=True, timeout=10, shell=False,
        )
        pub = pub_proc.stdout.strip()
    except Exception as exc:
        return {"error": f"공개키 추출 실패: {exc}"}

    conf_text = (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {server_address}\n"
        f"ListenPort = {listen_port}\n"
        "# PostUp / PostDown — 필요 시 NAT 규칙 추가\n"
        "# PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
        "# PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n"
    )

    if IS_WINDOWS:
        conf_dir  = _WG_WIN_CONF_DIR
        conf_path = os.path.join(conf_dir, f"{interface}.conf")
        try:
            os.makedirs(conf_dir, exist_ok=True)
            with open(conf_path, "w") as f:
                f.write(conf_text)
        except PermissionError:
            return {"error": f"권한 오류: 관리자 권한으로 앱을 실행하십시오.\n경로: {conf_path}"}
        except Exception as exc:
            return {"error": str(exc)}
    else:
        conf_path = f"/etc/wireguard/{interface}.conf"
        # /etc/wireguard 는 root 소유 → sudo tee 사용
        write_r = _run_local(
            ["sudo", "tee", conf_path],
        )
        # tee 는 stdin 이 필요하므로 subprocess 직접 호출
        try:
            proc = subprocess.run(
                ["sudo", "tee", conf_path],
                input=conf_text,
                capture_output=True, text=True, timeout=10, shell=False,
            )
            if proc.returncode != 0:
                return {"error": f"설정 파일 쓰기 실패: {proc.stderr}"}
            # 권한 제한 (소유자 읽기 전용)
            subprocess.run(["sudo", "chmod", "600", conf_path],
                           capture_output=True, shell=False)
        except Exception as exc:
            return {"error": str(exc)}

    return {"priv": priv, "pub": pub,
            "conf_path": conf_path, "conf_text": conf_text, "error": None}


def wg_up(interface: str = "wg0") -> str:
    if IS_WINDOWS:
        conf_path = os.path.join(_WG_WIN_CONF_DIR, f"{interface}.conf")
        if not os.path.isfile(conf_path):
            return f"❌ 설정 파일 없음: {conf_path}\n먼저 '서버 설정 생성'을 실행하십시오."
        exe = _WG_WIN_EXE if os.path.isfile(_WG_WIN_EXE) else "wireguard"
        r = _run_local([exe, "/installtunnelservice", conf_path])
    else:
        r = _run_local(["sudo", "wg-quick", "up", interface])
    if _check_perm(r):
        return r["stderr"]
    return r["stdout"] or r["stderr"] or "완료"


def wg_down(interface: str = "wg0") -> str:
    if IS_WINDOWS:
        exe = _WG_WIN_EXE if os.path.isfile(_WG_WIN_EXE) else "wireguard"
        r = _run_local([exe, "/uninstalltunnelservice", interface])
    else:
        r = _run_local(["sudo", "wg-quick", "down", interface])
    if _check_perm(r):
        return r["stderr"]
    return r["stdout"] or r["stderr"] or "완료"


def wg_show_peers() -> str:
    """접속 중인 피어 및 트래픽 정보."""
    wg_bin = _wg_exe()
    if IS_WINDOWS:
        r = _run_local([wg_bin, "show"])
    else:
        r = _run_local(["sudo", wg_bin, "show"])
    if _check_perm(r):
        return ""
    return r["stdout"] or "(접속 중인 피어 없음)"


def generate_keypair() -> tuple[str, str]:
    """
    wg genkey / wg pubkey 로 키 쌍 생성.
    반환: (private_key, public_key) — 실패 시 ("", "")
    """
    priv_r = _run_local(["wg", "genkey"])
    if priv_r["exit_code"] != 0 or not priv_r["stdout"].strip():
        return "", ""
    private_key = priv_r["stdout"].strip()
    try:
        pub_proc = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        return private_key, pub_proc.stdout.strip()
    except Exception:
        return private_key, ""


def make_client_conf(
    client_privkey: str,
    server_pubkey: str,
    server_endpoint: str,
    client_address: str,
    dns: str = "1.1.1.1",
    allowed_ips: str = "0.0.0.0/0",
) -> str:
    """WireGuard 클라이언트 .conf 문자열 생성."""
    return (
        "[Interface]\n"
        f"PrivateKey = {client_privkey}\n"
        f"Address = {client_address}/32\n"
        f"DNS = {dns}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_pubkey}\n"
        f"Endpoint = {server_endpoint}\n"
        f"AllowedIPs = {allowed_ips}\n"
        "PersistentKeepalive = 25\n"
    )


def conf_to_qr_png(conf_text: str) -> Optional[bytes]:
    """설정 파일 텍스트 → PNG bytes (QR 코드)."""
    if not _QR_AVAILABLE:
        return None
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=6,
        border=2,
    )
    qr.add_data(conf_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ===========================================================================
# Streamlit UI
# ===========================================================================
st.set_page_config(
    page_title="SecOps Local Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.markdown(_CSS, unsafe_allow_html=True)

# ===========================================================================
# SIDEBAR — system info
# ===========================================================================
with st.sidebar:
    st.title("🛡️ SecOps Local")
    st.caption("Local PC Security Dashboard")
    st.divider()

    st.subheader("💻 시스템 정보")
    st.markdown(
        f'<div class="info-card">'
        f'<b>OS:</b> {_OS} {platform.release()}<br>'
        f'<b>호스트명:</b> {platform.node()}<br>'
        f'<b>Python:</b> {sys.version.split()[0]}<br>'
        f'<b>아키텍처:</b> {platform.machine()}'
        f'</div>',
        unsafe_allow_html=True,
    )

    st.divider()
    fw_label = "Windows Firewall (netsh)" if IS_WINDOWS else "iptables (Linux)"
    st.info(f"**방화벽 엔진:** {fw_label}")

    if IS_WINDOWS:
        st.warning(
            "Windows 방화벽 제어는 **관리자 권한**이 필요합니다.\n\n"
            "관리자 CMD/PowerShell 에서 앱을 실행하십시오."
        )
    else:
        st.warning(
            "iptables 제어는 **root/sudo** 권한이 필요합니다.\n\n"
            "`sudo streamlit run app.py` 로 실행하십시오."
        )

    st.divider()
    st.caption(
        "⚠️ 이 앱을 `0.0.0.0` 으로 바인딩하면 같은 네트워크의 "
        "모든 기기에서 접속 가능합니다. 신뢰 네트워크에서만 사용하십시오."
    )


# ===========================================================================
# Tabs
# ===========================================================================
tab_analyze, tab_status, tab_fw, tab_vpn = st.tabs([
    "📧 텍스트 분석",
    "🖥️ 내 PC 보안 상태",
    "🔥 방화벽 제어",
    "🌐 VPN 가디언",
])


# ============================================================
# TAB 1 — Text Analysis
# ============================================================
with tab_analyze:
    st.header("의심 메시지 위험도 분석")

    user_text = st.text_area(
        "분석할 텍스트 입력 (SMS · 이메일 · URL):",
        height=160,
        placeholder="[긴급] 귀하의 계정이 정지되었습니다. 즉시 확인: http://1.2.3.4/verify",
    )

    if st.button("🔍 위험도 분석", type="primary", use_container_width=True):
        if not user_text.strip():
            st.warning("텍스트를 입력해주세요.")
        else:
            result = analyze_text(user_text)
            st.session_state["last_result"] = result

            st.markdown(f"### {result['badge']}  ·  {result['score']} / 100점")
            st.caption(f"분석 시각: {result['timestamp'].split('T')[1]}")

            if result["findings"]:
                st.warning("**탐지된 위협 지표**")
                for f in result["findings"]:
                    st.markdown(f"- {f}")
            else:
                st.success("위협 지표가 발견되지 않았습니다.")

    if "last_result" in st.session_state:
        with st.expander("마지막 분석 결과 (JSON)"):
            st.json(st.session_state["last_result"])


# ============================================================
# TAB 2 — PC Security Status
# ============================================================
with tab_status:
    st.header("🖥️ 내 PC 보안 상태")

    # ── Network connections ──────────────────────────────────
    st.subheader("🌐 활성 네트워크 연결 (ESTABLISHED)")
    if st.button("🔄 연결 상태 조회", use_container_width=True):
        with st.spinner("조회 중..."):
            conns = get_network_connections()
        st.code(conns, language="text")

    st.divider()

    # ── Listening ports ──────────────────────────────────────
    st.subheader("👂 LISTEN 중인 포트")
    if st.button("🔄 포트 목록 조회", use_container_width=True):
        with st.spinner("조회 중..."):
            ports = get_listening_ports()
        st.code(ports, language="text")

    st.divider()

    # ── Process list ─────────────────────────────────────────
    st.subheader("⚙️ 실행 중인 프로세스")

    proc_filter = st.text_input(
        "프로세스 이름 필터 (선택):",
        placeholder="예: python, chrome, svchost",
        key="proc_filter",
    )

    if st.button("🔄 프로세스 목록 조회", use_container_width=True):
        with st.spinner("조회 중..."):
            procs = get_process_list()

        if proc_filter.strip():
            # 헤더 + 필터 매칭 라인만 표시
            header_lines = procs.splitlines()[:2]
            matched_lines = [
                line for line in procs.splitlines()
                if proc_filter.lower() in line.lower()
            ]
            filtered = "\n".join(header_lines + matched_lines)
            st.code(filtered or "(매칭 결과 없음)", language="text")
            st.caption(f"'{proc_filter}' 포함 프로세스: {len(matched_lines)}개")
        else:
            st.code(procs, language="text")


# ============================================================
# TAB 3 — Firewall Control
# ============================================================
with tab_fw:
    st.header("방화벽 규칙 관리")
    fw_engine = "Windows Firewall (netsh)" if IS_WINDOWS else "iptables"
    st.info(f"방화벽 엔진: **{fw_engine}** · OS: **{_OS}**")

    st.error(
        "⚠️ 이 기능은 현재 PC의 방화벽 규칙을 직접 수정합니다. "
        "반드시 내용을 확인 후 승인하십시오."
    )

    if st.button("📋 현재 방화벽 규칙 조회", use_container_width=True):
        with st.spinner("조회 중..."):
            rules = get_firewall_rules()
        if rules:
            st.code(rules, language="text")

    # ── Block ──────────────────────────────────────────────
    st.divider()
    st.subheader("🚫 IP / 도메인 차단")

    raw_block = st.text_input(
        "차단할 IP 또는 도메인:",
        placeholder="예: 203.0.113.42 또는 phishing-site.com",
        key="block_input",
    )

    if raw_block:
        kind, b_ips = resolve_target(raw_block)

        if kind == "invalid":
            st.error("⚠️ 유효한 주소를 입력하세요. (IPv4 또는 도메인)")
        elif kind == "domain" and not b_ips:
            st.error(f"⚠️ 도메인 `{raw_block}` DNS 조회 실패")
        else:
            if kind == "domain":
                st.info(f"도메인 **{raw_block}** → IPv4 **{', '.join(b_ips)}** 차단 예정")

            # Preview commands
            if IS_WINDOWS:
                preview = "\n".join(
                    f'netsh advfirewall firewall add rule name="SecOps_Block_{ip}_inbound" '
                    f'dir=in action=block remoteip={ip}\n'
                    f'netsh advfirewall firewall add rule name="SecOps_Block_{ip}_outbound" '
                    f'dir=out action=block remoteip={ip}'
                    for ip in b_ips
                )
            else:
                preview = "\n".join(
                    f"sudo iptables -I INPUT  -s {ip} -j DROP\n"
                    f"sudo iptables -I OUTPUT -d {ip} -j DROP"
                    for ip in b_ips
                )

            with st.expander("실행 예정 명령어 확인", expanded=True):
                st.code(preview, language="bash")

            if st.checkbox(
                f"{len(b_ips)}개 IP를 현재 PC에서 차단하는 것에 동의합니다.",
                key="block_confirm",
            ):
                if st.button("🚫 차단 실행", type="primary", use_container_width=True):
                    with st.spinner("차단 중..."):
                        out = block_ips(b_ips)
                    if out:
                        st.code(out, language="text")
                    if "exit: 0" in out and "exit: -1" not in out:
                        st.success(f"✅ {len(b_ips)}개 IP 차단 완료")
                    else:
                        st.error("오류가 발생했습니다. 위 출력을 확인하세요.")

    # ── Unblock ────────────────────────────────────────────
    st.divider()
    st.subheader("🔓 차단 해제 (IP 또는 도메인)")

    raw_unblock = st.text_input(
        "해제할 IP 또는 도메인:",
        placeholder="예: 203.0.113.42 또는 example.com",
        key="unblock_input",
    )

    if raw_unblock:
        u_kind, u_ips = resolve_target(raw_unblock)

        if u_kind == "invalid":
            st.error("⚠️ 유효한 주소를 입력하세요.")
        elif u_kind == "domain" and not u_ips:
            st.error(f"⚠️ 도메인 `{raw_unblock}` DNS 조회 실패")
        else:
            if u_kind == "domain":
                st.info(f"도메인 **{raw_unblock}** → IP **{', '.join(u_ips)}** 해제 예정")

            if st.button("🔓 차단 해제 실행", use_container_width=True):
                with st.spinner("해제 중..."):
                    r_kind, r_ips, r_out = unblock_target_local(raw_unblock)
                if r_out:
                    st.code(r_out, language="text")
                if r_ips and "exit: 0" in r_out:
                    label = (
                        f"도메인 {raw_unblock} (→ {', '.join(r_ips)})"
                        if r_kind == "domain" else f"IP {raw_unblock}"
                    )
                    st.success(f"✅ {label} 차단 규칙이 삭제되었습니다.")
                    with st.spinner("규칙 새로고침 중..."):
                        st.code(get_firewall_rules(), language="text")
                else:
                    st.warning("규칙 삭제 실패. 해당 규칙이 없거나 형식이 다를 수 있습니다.")

    # ── Flush ──────────────────────────────────────────────
    st.divider()
    st.subheader("🗑️ SecOps 차단 규칙 전체 초기화")

    flush_scope = (
        "이 앱이 추가한 `SecOps_Block_*` 규칙만 삭제합니다."
        if IS_WINDOWS else
        "INPUT/OUTPUT 체인의 **모든** iptables 규칙이 삭제됩니다."
    )
    st.error(f"⚠️ {flush_scope}")

    chk1 = st.checkbox("전체 삭제의 영향을 충분히 이해했습니다.", key="flush_chk1")
    chk2 = st.checkbox(
        "현재 PC의 모든 SecOps 차단 규칙 삭제에 동의합니다.",
        key="flush_chk2",
        disabled=not chk1,
    )

    if chk1 and chk2:
        if st.button("🗑️ 전체 삭제 실행", type="primary", use_container_width=True):
            with st.spinner("초기화 중..."):
                out = flush_firewall()
            if out:
                st.code(out, language="text")
            if "exit: 0" in out and "exit: -1" not in out:
                st.success("✅ 차단 규칙 초기화 완료")
                with st.spinner("규칙 새로고침 중..."):
                    st.code(get_firewall_rules(), language="text")
            else:
                st.error("초기화 중 오류가 발생했습니다.")


# ============================================================
# TAB 4 — VPN 가디언 (WireGuard)
# ============================================================
with tab_vpn:
    st.header("🌐 VPN 가디언 — WireGuard 관리")

    # ── 설치 및 권한 확인 ─────────────────────────────────
    status = wg_status()

    if not status["installed"]:
        st.error("WireGuard 가 설치되어 있지 않습니다.")
        if IS_WINDOWS:
            st.info(
                f"**설치 경로 확인:** `{_WG_WIN_EXE}`\n\n"
                "해당 경로에 파일이 없으면 공식 사이트에서 설치하세요:\n"
                "https://www.wireguard.com/install/"
            )
        with st.expander("OS별 설치 명령어"):
            st.code(
                "# Ubuntu / Debian\n"
                "sudo apt update && sudo apt install -y wireguard\n\n"
                "# CentOS / RHEL 8+\n"
                "sudo dnf install -y wireguard-tools\n\n"
                "# macOS\n"
                "brew install wireguard-tools\n\n"
                "# Windows — 공식 설치 프로그램 사용\n"
                "# https://www.wireguard.com/install/",
                language="bash",
            )
        st.stop()

    # Windows 관리자 권한 경고
    if IS_WINDOWS and not status["admin_ok"]:
        st.error(
            "🔒 **관리자 권한이 없습니다.**\n\n"
            "WireGuard 서비스 제어와 방화벽 규칙 적용에는 관리자 권한이 필요합니다.\n\n"
            "**해결 방법:** CMD 또는 PowerShell 을 "
            "**'관리자 권한으로 실행'** 한 후 앱을 재시작하십시오."
        )
        st.warning("읽기 전용 기능(키 생성, 설정 파일 작성)은 계속 사용할 수 있습니다.")

    # ── VPN 상태 카드 ──────────────────────────────────────
    running    = status["running"]
    state_icon = "🟢 실행 중" if running else "🔴 중지됨"
    admin_icon = "✅ 관리자" if status.get("admin_ok", True) else "⚠️ 일반 사용자"
    wg_path_label = _WG_WIN_EXE if IS_WINDOWS else "wg (PATH)"

    st.markdown(
        f'<div class="info-card">'
        f'<b>상태:</b> {state_icon} &nbsp;|&nbsp; '
        f'<b>권한:</b> {admin_icon}<br>'
        f'<small style="opacity:.7">경로: {wg_path_label}</small>'
        f'</div>',
        unsafe_allow_html=True,
    )

    iface = st.text_input("인터페이스 이름:", value="wg0", key="wg_iface")

    col_up, col_down = st.columns(2)
    with col_up:
        if st.button("▶️ VPN 시작", use_container_width=True, type="primary"):
            with st.spinner(f"wg-quick up {iface} ..."):
                out = wg_up(iface)
            if out:
                st.code(out, language="text")
            st.rerun()
    with col_down:
        if st.button("⏹️ VPN 중지", use_container_width=True):
            with st.spinner(f"wg-quick down {iface} ..."):
                out = wg_down(iface)
            if out:
                st.code(out, language="text")
            st.rerun()

    # ── 서버 설정 자동 생성 ───────────────────────────────
    st.divider()
    st.subheader("⚙️ VPN 서버 초기 설정 생성")

    if IS_WINDOWS:
        conf_exists = os.path.isfile(
            os.path.join(_WG_WIN_CONF_DIR, f"{iface}.conf")
        )
    else:
        conf_exists = os.path.isfile(f"/etc/wireguard/{iface}.conf")

    if conf_exists:
        st.success(f"✅ `{iface}.conf` 이미 존재합니다. 아래에서 덮어쓸 수 있습니다.")

    with st.form("server_conf_form"):
        sv_addr    = st.text_input("서버 VPN 주소 (CIDR):", value="10.0.0.1/24")
        sv_port    = st.number_input("수신 포트:", value=51820,
                                     min_value=1024, max_value=65535)
        sv_confirm = st.checkbox(
            "기존 설정 파일을 덮어씁니다." if conf_exists else "새 설정 파일을 생성합니다."
        )
        sv_btn = st.form_submit_button(
            "🔧 서버 키 생성 및 wg0.conf 작성",
            use_container_width=True, type="primary",
        )

    if sv_btn:
        if not sv_confirm:
            st.warning("체크박스를 선택해야 실행됩니다.")
        else:
            with st.spinner("키 생성 및 설정 파일 작성 중..."):
                result = create_server_config(
                    interface=iface,
                    server_address=sv_addr,
                    listen_port=int(sv_port),
                )

            if result.get("error"):
                st.error(f"오류: {result['error']}")
            else:
                st.session_state["server_pub"]  = result["pub"]
                st.session_state["server_conf"] = result["conf_text"]
                st.session_state["server_port"] = int(sv_port)

                st.success(f"✅ 서버 설정 생성 완료 → `{result['conf_path']}`")
                st.info(
                    f"**서버 Public Key** (클라이언트 [Peer] PublicKey 에 사용):\n\n"
                    f"```\n{result['pub']}\n```"
                )
                with st.expander("생성된 wg0.conf 내용 (개인키 포함 — 주의)", expanded=False):
                    st.code(result["conf_text"], language="ini")

                if IS_WINDOWS:
                    st.info(
                        "**다음 단계:** 아래 'VPN 시작' 버튼을 누르면\n\n"
                        f"`wireguard.exe /installtunnelservice {result['conf_path']}`\n\n"
                        "명령이 실행됩니다."
                    )

    # ── 접속 현황 ──────────────────────────────────────────
    st.divider()
    st.subheader("📊 피어 접속 현황 및 트래픽")
    if st.button("🔄 현황 새로고침", use_container_width=True):
        with st.spinner("wg show 실행 중..."):
            peers_out = wg_show_peers()
        if peers_out:
            st.code(peers_out, language="text")

            # 간단한 피어 파싱 — peer 블록 단위 카드 표시
            peer_blocks = peers_out.split("peer:")
            if len(peer_blocks) > 1:
                st.subheader(f"탐지된 피어: {len(peer_blocks)-1}개")
                for block in peer_blocks[1:]:
                    lines_b = block.strip().splitlines()
                    pubkey_short = lines_b[0].strip()[:20] + "…" if lines_b else "?"
                    info = "\n".join(lines_b[:6])
                    st.markdown(
                        f'<div class="info-card">'
                        f'<b>Peer:</b> <code>{pubkey_short}</code><br>'
                        f'<pre style="margin:4px 0;font-size:12px">{info}</pre>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

    # ── 클라이언트 추가 ────────────────────────────────────
    st.divider()
    st.subheader("➕ 새 클라이언트 설정 생성")
    st.warning(
        "⚠️ 생성된 설정에는 **개인키(Private Key)** 가 포함됩니다. "
        "QR 코드를 화면 캡처하거나 제3자에게 공유하지 마십시오."
    )

    # 서버 설정 생성 후 자동 채우기
    _srv_pub_default  = st.session_state.get("server_pub", "")
    _srv_port_default = st.session_state.get("server_port", 51820)

    with st.form("new_client_form"):
        c_name     = st.text_input("클라이언트 이름:", placeholder="예: my-phone")
        c_addr     = st.text_input("클라이언트 IP:", value="10.0.0.2",
                                   help="서버 VPN 서브넷 내 미사용 IP")
        c_server_pub = st.text_input(
            "서버 Public Key:",
            value=_srv_pub_default,
            placeholder="서버의 wg pubkey 값 — 위 '서버 설정 생성' 후 자동 입력됨",
        )
        c_endpoint = st.text_input(
            "서버 Endpoint:",
            placeholder=f"예: 203.0.113.1:{_srv_port_default}",
        )
        c_dns      = st.text_input("DNS:", value="1.1.1.1")
        c_allowed  = st.text_input("AllowedIPs:", value="0.0.0.0/0")

        gen_btn = st.form_submit_button("🔑 키 생성 및 설정 파일 만들기",
                                        use_container_width=True, type="primary")

    if gen_btn:
        if not c_server_pub or not c_endpoint:
            st.error("서버 Public Key 와 Endpoint 는 필수입니다.")
        else:
            with st.spinner("키 생성 중..."):
                priv, pub = generate_keypair()

            if not priv:
                st.error(
                    "키 생성 실패 — `wg` 명령을 찾을 수 없습니다. "
                    "WireGuard 가 PATH 에 있는지 확인하십시오."
                )
            else:
                conf_text = make_client_conf(
                    client_privkey=priv,
                    server_pubkey=c_server_pub,
                    server_endpoint=c_endpoint,
                    client_address=c_addr,
                    dns=c_dns,
                    allowed_ips=c_allowed,
                )
                # session state 에 저장 (디스크 기록 없음)
                st.session_state["last_conf"]     = conf_text
                st.session_state["last_conf_name"] = c_name or "client"
                st.session_state["last_pub"]      = pub

                st.success(f"✅ '{c_name}' 설정 생성 완료")
                st.info(
                    f"**클라이언트 Public Key** (서버 wg0.conf 의 [Peer] 에 추가):\n\n"
                    f"```\n{pub}\n```"
                )

    # 생성된 설정 표시
    if "last_conf" in st.session_state:
        conf = st.session_state["last_conf"]
        name = st.session_state.get("last_conf_name", "client")

        st.divider()
        st.subheader(f"📄 '{name}' 설정 파일")

        with st.expander("설정 파일 내용 보기 (개인키 포함 — 주의)", expanded=False):
            st.code(conf, language="ini")

        # 다운로드 버튼
        st.download_button(
            label="💾 .conf 파일 다운로드",
            data=conf,
            file_name=f"{name}.conf",
            mime="text/plain",
            use_container_width=True,
        )

        # QR 코드
        st.subheader("📱 스마트폰 QR 코드 스캔")
        if not _QR_AVAILABLE:
            st.warning("`pip install qrcode[pil]` 설치 후 재시작하면 QR 코드가 표시됩니다.")
        else:
            png = conf_to_qr_png(conf)
            if png:
                st.warning("⚠️ 이 QR 코드는 개인키를 포함합니다. 촬영 후 즉시 화면을 닫으십시오.")
                st.image(png, caption=f"{name} — WireGuard QR", width=280)
            else:
                st.error("QR 코드 생성에 실패했습니다.")
