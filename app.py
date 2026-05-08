"""
SecOps Automation Dashboard
Authorized Internal Security Lab — University Training Environment

자격 증명은 코드에 하드코딩하지 않고 환경 변수 또는
.streamlit/secrets.toml 에서 로드합니다.

Required env vars:
  SSH_USER      - SSH 접속 사용자명 (예: analyst)
  SSH_KEY_PATH  - SSH 개인키 경로 (예: /home/analyst/.ssh/id_rsa)
  SSH_PORT      - SSH 포트 (기본값: 22)
"""

import os
import re
import socket
import logging
from datetime import datetime
from typing import Optional

import paramiko
import streamlit as st

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secops")

# ---------------------------------------------------------------------------
# Server inventory — 접속 대상 정의
# ---------------------------------------------------------------------------
SERVERS: dict[str, dict] = {
    "security-gateway": {
        "host": "192.168.112.129",
        "user": "security",          # 서버별 계정
        "role": "Security Gateway",
        "icon": "🔒",
    },
    "web-server": {
        "host": "192.168.112.130",
        "user": "web",
        "role": "Web Server",
        "icon": "🌐",
    },
    "siem": {
        "host": "192.168.112.131",
        "user": "siem",
        "role": "SIEM Server",
        "icon": "📊",
    },
}

# ---------------------------------------------------------------------------
# Credential helper — 환경 변수 우선, st.secrets 폴백
# ---------------------------------------------------------------------------
def _get_secret(key: str, default: str = "") -> str:
    """환경 변수 → st.secrets → default 순서로 값을 읽는다."""
    env_val = os.environ.get(key)
    if env_val:
        return env_val
    try:
        return st.secrets.get(key, default)
    except Exception:
        return default


def _ssh_password() -> tuple[str, int]:
    """(password, port) 반환. 비밀번호는 SERVER_PASS 환경 변수 → 기본값 '1'."""
    password = _get_secret("SERVER_PASS", "1")   # 랩 기본값
    port = int(_get_secret("SSH_PORT", "22"))
    return password, port


# 호스트 → 서버별 계정 역방향 조회
_HOST_USER: dict[str, str] = {
    info["host"]: info["user"] for info in SERVERS.values()
}


# ---------------------------------------------------------------------------
# SSH connection helper — 비밀번호 인증 (랩 환경)
# ---------------------------------------------------------------------------
def _connect(host: str) -> Optional[paramiko.SSHClient]:
    """
    비밀번호 인증으로 SSH 연결한다.
    계정은 서버별로 SERVERS 에 정의된 값을 사용하고,
    비밀번호는 환경 변수 SERVER_PASS (기본값: '1') 에서 로드한다.
    """
    password, port = _ssh_password()
    username = _HOST_USER.get(host, "root")   # 매핑 없으면 root 폴백

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        return client
    except paramiko.AuthenticationException:
        st.error(f"인증 실패 ({host}, user={username}). 계정·비밀번호를 확인하세요.")
    except paramiko.SSHException as exc:
        st.error(f"SSH 프로토콜 오류 ({host}): {exc}")
    except OSError as exc:
        st.error(f"연결 오류 ({host}): {exc}")
    return None


def _run(client: paramiko.SSHClient, command: str, timeout: int = 30) -> dict:
    """명령 실행 후 {'stdout', 'stderr', 'exit_code'} 반환."""
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        return {
            "stdout": stdout.read().decode("utf-8", errors="replace"),
            "stderr": stderr.read().decode("utf-8", errors="replace"),
            "exit_code": stdout.channel.recv_exit_status(),
        }
    except Exception as exc:
        return {"stdout": "", "stderr": str(exc), "exit_code": -1}


def _run_sudo(client: paramiko.SSHClient, command: str, timeout: int = 30) -> dict:
    """
    sudo 가 필요한 명령을 실행한다.
    paramiko stdin 에 비밀번호를 주입하여 'sudo: a password is required' 를 방지.
    """
    password, _ = _ssh_password()
    try:
        stdin, stdout, stderr = client.exec_command(
            f"sudo -S {command}", timeout=timeout
        )
        stdin.write(f"{password}\n")
        stdin.flush()
        return {
            "stdout": stdout.read().decode("utf-8", errors="replace"),
            "stderr": stderr.read().decode("utf-8", errors="replace"),
            "exit_code": stdout.channel.recv_exit_status(),
        }
    except Exception as exc:
        return {"stdout": "", "stderr": str(exc), "exit_code": -1}


# ---------------------------------------------------------------------------
# Risk Analysis Engine — 피싱/스미싱 위험도 판정
# ---------------------------------------------------------------------------
_PHISHING_KEYWORDS = [
    # 한국어
    "긴급", "확인", "계정", "정지", "클릭", "비밀번호", "로그인", "보안",
    "업데이트", "당첨", "무료", "이벤트", "인증", "보상", "탈취",
    # 영어
    "urgent", "verify", "account", "suspended", "click here", "limited time",
    "confirm your", "password", "login", "security alert", "update required",
    "unusual activity", "prize", "winner", "free gift",
]

_SUSPICIOUS_URL_RE = [
    re.compile(r"http://(?!\S+\.(?:gov|edu|mil|or\.kr))\S+", re.I),  # 비보안 HTTP
    re.compile(r"\d{1,3}(?:\.\d{1,3}){3}", re.I),                    # IP 주소 URL
    re.compile(r"(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd)/\S+", re.I),  # URL 단축기
]


def analyze_text(text: str) -> dict:
    """텍스트의 피싱/스미싱 위험도를 분석하여 결과 dict 반환."""
    text_lower = text.lower()
    score = 0
    findings: list[str] = []

    # 키워드 탐지
    matched = [kw for kw in _PHISHING_KEYWORDS if kw in text_lower]
    if matched:
        score += len(matched) * 10
        findings.append(f"의심 키워드 발견: `{', '.join(matched)}`")

    # URL 패턴 탐지
    for pattern in _SUSPICIOUS_URL_RE:
        hits = pattern.findall(text)
        if hits:
            score += 20
            findings.append(f"의심 URL 패턴: `{hits[0]}`")

    # 짧은 긴급 메시지 (스미싱 전형)
    if len(text) < 120 and score > 0:
        score += 15
        findings.append("짧은 긴급 메시지 구조 (스미싱 전형 패턴)")

    score = min(score, 100)

    if score >= 60:
        risk_level, badge = "HIGH",   "🔴 HIGH"
    elif score >= 30:
        risk_level, badge = "MEDIUM", "🟡 MEDIUM"
    else:
        risk_level, badge = "LOW",    "🟢 LOW"

    return {
        "score": score,
        "risk_level": risk_level,
        "badge": badge,
        "findings": findings,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }


# ---------------------------------------------------------------------------
# Remote Action Functions
# ---------------------------------------------------------------------------
def fetch_log(host: str, log_path: str, lines: int = 50) -> str:
    client = _connect(host)
    if client is None:
        return "⚠️ 연결 실패"
    try:
        result = _run(client, f"tail -n {lines} {log_path}")
        return result["stdout"] or result["stderr"] or "(내용 없음)"
    finally:
        client.close()


def fetch_active_connections(host: str) -> str:
    client = _connect(host)
    if client is None:
        return "⚠️ 연결 실패"
    try:
        result = _run(client, "ss -tnp state established 2>/dev/null | head -30")
        return result["stdout"] or "(활성 연결 없음)"
    finally:
        client.close()


def fetch_iptables_rules(host: str) -> str:
    client = _connect(host)
    if client is None:
        return "⚠️ 연결 실패"
    try:
        result = _run_sudo(client, "iptables -L INPUT -n --line-numbers 2>&1 | head -40")
        return result["stdout"] or result["stderr"]
    finally:
        client.close()


_IP_RE     = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$")
_PROTECTED = ("127.", "0.0.0.0", "192.168.112.128")


def resolve_target(target: str) -> tuple[str, list[str]]:
    """
    입력값이 IP인지 도메인인지 판별하고 차단할 IP 목록을 반환한다.
    반환: (kind, ip_list)
      kind  — "ip" | "domain" | "invalid"
      ip_list — 차단 대상 IP 리스트 (실패 시 빈 리스트)
    """
    target = target.strip()

    if _IP_RE.match(target):
        return "ip", [target]

    if _DOMAIN_RE.match(target):
        try:
            infos = socket.getaddrinfo(target, None)
            # IPv4 만 추출 (AF_INET), IPv6(2404:… 등) 제외
            ips = list(dict.fromkeys(
                info[4][0]
                for info in infos
                if info[0] == socket.AF_INET   # AF_INET = IPv4 only
            ))
            return "domain", ips
        except socket.gaierror:
            return "domain", []   # DNS 조회 실패

    return "invalid", []


def block_ip(host: str, ip: str) -> str:
    """iptables 로 단일 IP를 INPUT/OUTPUT 양방향 차단."""
    if not _IP_RE.match(ip):
        return "⚠️ 유효하지 않은 IP 형식"
    if any(ip.startswith(p) for p in _PROTECTED):
        return "⚠️ 보호된 주소 — 차단 거부됨"

    client = _connect(host)
    if client is None:
        return "⚠️ 연결 실패"
    try:
        lines = []
        for cmd in [
            f"iptables -I INPUT  -s {ip} -j DROP",
            f"iptables -I OUTPUT -d {ip} -j DROP",
        ]:
            r = _run_sudo(client, cmd)
            lines.append(f"$ sudo {cmd}")
            if r["stdout"]:
                lines.append(r["stdout"])
            if r["stderr"]:
                lines.append(f"[stderr] {r['stderr']}")
            lines.append(f"exit: {r['exit_code']}")
        return "\n".join(lines)
    finally:
        client.close()


def unblock_ip(host: str, ip: str) -> str:
    """iptables -D 로 단일 IP 차단 규칙을 삭제한다."""
    if not _IP_RE.match(ip):
        return "⚠️ 유효하지 않은 IP 형식"

    client = _connect(host)
    if client is None:
        return "⚠️ 연결 실패"
    try:
        lines = []
        for cmd in [
            f"iptables -D INPUT  -s {ip} -j DROP",
            f"iptables -D OUTPUT -d {ip} -j DROP",
        ]:
            r = _run_sudo(client, cmd)
            lines.append(f"$ sudo {cmd}")
            if r["stdout"]:
                lines.append(r["stdout"])
            if r["stderr"]:
                lines.append(f"[stderr] {r['stderr']}")
            lines.append(f"exit: {r['exit_code']}")
        return "\n".join(lines)
    finally:
        client.close()


def unblock_target(host: str, target: str) -> tuple[str, list[str], str]:
    """
    IP 또는 도메인을 입력받아 차단 규칙을 삭제한다.
    resolve_target() 로 IPv4 목록을 구한 뒤 unblock_ip() 를 순차 호출.
    반환: (kind, resolved_ips, output_text)
    """
    kind, ips = resolve_target(target)

    if kind == "invalid":
        return kind, [], "⚠️ 유효한 주소를 입력하세요. (IPv4 또는 도메인 형식)"

    if kind == "domain" and not ips:
        return kind, [], f"⚠️ 도메인 `{target}` 의 DNS 조회에 실패했습니다."

    client = _connect(host)
    if client is None:
        return kind, ips, "⚠️ 연결 실패"

    try:
        lines = []
        for ip in ips:
            for cmd in [
                f"iptables -D INPUT  -s {ip} -j DROP",
                f"iptables -D OUTPUT -d {ip} -j DROP",
            ]:
                r = _run_sudo(client, cmd)
                lines.append(f"$ sudo {cmd}")
                if r["stdout"]:
                    lines.append(r["stdout"])
                if r["stderr"]:
                    lines.append(f"[stderr] {r['stderr']}")
                lines.append(f"exit: {r['exit_code']}")
        return kind, ips, "\n".join(lines)
    finally:
        client.close()


def flush_iptables(host: str) -> str:
    """iptables -F 로 INPUT/OUTPUT 체인의 모든 규칙을 초기화한다."""
    client = _connect(host)
    if client is None:
        return "⚠️ 연결 실패"
    try:
        lines = []
        for cmd in ["iptables -F INPUT", "iptables -F OUTPUT"]:
            r = _run_sudo(client, cmd)
            lines.append(f"$ sudo {cmd}")
            if r["stdout"]:
                lines.append(r["stdout"])
            if r["stderr"]:
                lines.append(f"[stderr] {r['stderr']}")
            lines.append(f"exit: {r['exit_code']}")
        return "\n".join(lines)
    finally:
        client.close()


def block_multiple_ips(host: str, ips: list[str]) -> str:
    """IP 목록을 하나의 SSH 세션에서 순차 차단한다."""
    if any(ip.startswith(p) for ip in ips for p in _PROTECTED):
        blocked = [ip for ip in ips if any(ip.startswith(p) for p in _PROTECTED)]
        return f"⚠️ 보호된 주소 포함 — 차단 거부됨: {blocked}"

    client = _connect(host)
    if client is None:
        return "⚠️ 연결 실패"
    try:
        lines = []
        for ip in ips:
            if not _IP_RE.match(ip):
                lines.append(f"[SKIP] IPv4 형식 아님 (IPv6 제외): {ip}")
                continue
            for cmd in [
                f"iptables -I INPUT  -s {ip} -j DROP",
                f"iptables -I OUTPUT -d {ip} -j DROP",
            ]:
                r = _run_sudo(client, cmd)
                lines.append(f"$ sudo {cmd}")
                if r["stdout"]:
                    lines.append(r["stdout"])
                if r["stderr"]:
                    lines.append(f"[stderr] {r['stderr']}")
                lines.append(f"exit: {r['exit_code']}")
        return "\n".join(lines)
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SecOps Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Sidebar ---
with st.sidebar:
    st.title("🛡️ SecOps Dashboard")
    st.caption("Internal Security Lab · University Training")
    st.divider()

    # 자격 증명 상태 표시 (비밀번호 값 자체는 노출하지 않음)
    password, port = _ssh_password()
    st.subheader("⚙️ SSH 설정")
    st.write(f"**인증 방식:** 비밀번호 인증 ✅")
    st.write(f"**Password:** `{'*' * len(password)}`")
    st.write(f"**Port:** `{port}`")
    st.caption("비밀번호 변경: 환경 변수 `SERVER_PASS` 설정")

    st.divider()
    st.subheader("🖥️ 대상 서버")
    for info in SERVERS.values():
        st.write(f"{info['icon']} **{info['role']}**")
        st.caption(f"`{info['user']}@{info['host']}`")

# --- Main tabs ---
tab_analyze, tab_logs, tab_fw = st.tabs([
    "📧 텍스트 분석",
    "🔍 로그 조회",
    "🔥 방화벽 제어",
])

# ============================================================
# TAB 1 — 텍스트 분석
# ============================================================
with tab_analyze:
    st.header("의심 메시지 위험도 분석")

    sample = (
        "[긴급] 귀하의 계정이 정지되었습니다. "
        "즉시 확인하세요: http://1.2.3.4/verify"
    )
    user_text = st.text_area(
        "분석할 텍스트 입력 (SMS · 이메일 · URL):",
        height=160,
        placeholder=sample,
    )

    if st.button("🔍 위험도 분석", type="primary", use_container_width=True):
        if not user_text.strip():
            st.warning("텍스트를 입력해주세요.")
        else:
            result = analyze_text(user_text)
            st.session_state["last_result"] = result

            c1, c2, c3 = st.columns(3)
            c1.metric("위험 점수", f"{result['score']} / 100")
            c2.metric("위험 등급", result["badge"])
            c3.metric("분석 시각", result["timestamp"].split("T")[1])

            if result["findings"]:
                st.warning("**탐지된 위협 지표**")
                for f in result["findings"]:
                    st.markdown(f"- {f}")
            else:
                st.success("위협 지표가 발견되지 않았습니다.")

    # 이전 분석 결과 유지
    if "last_result" in st.session_state:
        r = st.session_state["last_result"]
        with st.expander("마지막 분석 결과 (JSON)", expanded=False):
            st.json(r)

# ============================================================
# TAB 2 — 로그 조회
# ============================================================
with tab_logs:
    st.header("원격 서버 로그 조회")

    col_s, col_l = st.columns(2)
    with col_s:
        log_target = st.selectbox(
            "대상 서버:",
            options=list(SERVERS.keys()),
            format_func=lambda k: f"{SERVERS[k]['icon']} {SERVERS[k]['role']} ({SERVERS[k]['host']})",
            key="log_target",
        )
    with col_l:
        log_file = st.selectbox(
            "로그 파일:",
            options=[
                ("/var/log/auth.log",          "인증 로그 (auth.log)"),
                ("/var/log/syslog",            "시스템 로그 (syslog)"),
                ("/var/log/nginx/access.log",  "Nginx 접근 로그"),
                ("/var/log/apache2/access.log","Apache 접근 로그"),
            ],
            format_func=lambda x: x[1],
        )

    log_lines = st.slider("조회 라인 수:", 10, 200, 50, step=10)

    st.info(
        f"SSH 접속 대상: **{SERVERS[log_target]['host']}** · "
        f"파일: `{log_file[0]}` · 마지막 {log_lines}줄"
    )

    col_ok, _ = st.columns([1, 5])
    if col_ok.button("✅ 승인 및 조회", type="primary"):
        with st.spinner("로그 조회 중..."):
            output = fetch_log(
                host=SERVERS[log_target]["host"],
                log_path=log_file[0],
                lines=log_lines,
            )
        st.code(output, language="text")

    st.divider()
    st.subheader("활성 네트워크 연결")
    if st.button("🔌 활성 연결 확인", key="btn_conn"):
        with st.spinner("연결 목록 조회 중..."):
            conns = fetch_active_connections(SERVERS[log_target]["host"])
        st.code(conns, language="text")

# ============================================================
# TAB 3 — 방화벽 제어
# ============================================================
with tab_fw:
    st.header("방화벽 규칙 관리 (iptables)")
    st.error(
        "⚠️ **주의:** 이 기능은 원격 서버의 방화벽 규칙을 수정합니다. "
        "잘못 적용하면 서버 접근이 차단될 수 있습니다. "
        "반드시 담당자 승인 후 사용하십시오."
    )

    fw_target = st.selectbox(
        "제어 대상 서버:",
        options=list(SERVERS.keys()),
        format_func=lambda k: f"{SERVERS[k]['icon']} {SERVERS[k]['role']} ({SERVERS[k]['host']})",
        key="fw_target",
    )
    fw_host = SERVERS[fw_target]["host"]

    # 현재 규칙 조회
    if st.button("📋 현재 iptables 규칙 조회"):
        with st.spinner("규칙 조회 중..."):
            rules = fetch_iptables_rules(fw_host)
        st.code(rules, language="text")

    st.divider()
    st.subheader("IP / 도메인 차단")

    raw_input = st.text_input(
        "차단할 IP 또는 도메인:",
        placeholder="예: 203.0.113.42  또는  phishing-site.com",
    )

    if raw_input:
        kind, resolved_ips = resolve_target(raw_input)

        if kind == "invalid":
            st.error("⚠️ 유효한 주소를 입력하세요. (IPv4 또는 도메인 형식)")

        elif kind == "domain" and not resolved_ips:
            st.error(f"⚠️ 도메인 `{raw_input}` 의 DNS 조회에 실패했습니다. 유효한 도메인인지 확인하세요.")

        else:
            # DNS 조회 결과 안내
            if kind == "domain":
                st.info(
                    f"도메인 **{raw_input}** 분석 결과, "
                    f"IP **{', '.join(resolved_ips)}** 을(를) 탐지하여 차단을 진행합니다."
                )
            else:
                st.info(f"IP 주소 **{resolved_ips[0]}** 차단을 진행합니다.")

            # 실행 예정 명령어 미리 보기
            preview_lines = []
            for ip in resolved_ips:
                preview_lines += [
                    f"sudo iptables -I INPUT  -s {ip} -j DROP",
                    f"sudo iptables -I OUTPUT -d {ip} -j DROP",
                ]
            st.warning(
                "**실행 예정 명령어 (사전 검토):**\n\n"
                f"```bash\n" + "\n".join(preview_lines) + f"\n```\n\n"
                f"적용 서버: **{fw_host}**"
            )

            confirmed = st.checkbox(
                f"위 {len(resolved_ips)}개 IP를 **{fw_host}** 에서 차단하는 것에 동의합니다.",
                key="fw_confirm",
            )

            if confirmed and st.button("🚫 차단 실행", type="primary"):
                with st.spinner(f"{len(resolved_ips)}개 IP 차단 중..."):
                    output = block_multiple_ips(fw_host, resolved_ips)
                st.code(output, language="text")
                if "exit: 0" in output and "exit: -1" not in output:
                    st.success(f"✅ 총 {len(resolved_ips)}개 IP 차단 완료")
                else:
                    st.error("일부 명령 실행 중 오류가 발생했습니다. 위 출력을 확인하세요.")

    # ----------------------------------------------------------
    # 차단 해제 섹션
    # ----------------------------------------------------------
    st.divider()
    st.subheader("🔓 차단 해제 (IP 또는 도메인)")

    unblock_input = st.text_input(
        "해제할 IP 또는 도메인:",
        placeholder="예: 203.0.113.42 또는 example.com",
        key="unblock_input",
    )

    if unblock_input:
        raw = unblock_input.strip()
        # 입력값 미리 분석 (버튼 누르기 전 명령어 미리 보기용)
        preview_kind, preview_ips = resolve_target(raw)

        if preview_kind == "invalid":
            st.error("⚠️ 유효한 주소를 입력하세요. (IPv4 또는 도메인 형식)")

        elif preview_kind == "domain" and not preview_ips:
            st.error(f"⚠️ 도메인 `{raw}` 의 DNS 조회에 실패했습니다.")

        else:
            if preview_kind == "domain":
                st.info(
                    f"도메인 **{raw}** → IP **{', '.join(preview_ips)}** 로 해제를 진행합니다."
                )

            preview_cmds = []
            for ip in preview_ips:
                preview_cmds += [
                    f"sudo iptables -D INPUT  -s {ip} -j DROP",
                    f"sudo iptables -D OUTPUT -d {ip} -j DROP",
                ]
            st.info(
                f"**실행 예정 명령어:**\n\n"
                f"```bash\n" + "\n".join(preview_cmds) + f"\n```\n\n"
                f"적용 서버: **{fw_host}**"
            )

            if st.button("🔓 차단 해제 실행", key="btn_unblock"):
                with st.spinner(f"{raw} 규칙 삭제 중..."):
                    kind, ips, out = unblock_target(fw_host, raw)
                st.code(out, language="text")
                if ips and "exit: 0" in out:
                    label = f"도메인 {raw} (→ {', '.join(ips)})" if kind == "domain" else f"IP {raw}"
                    st.success(f"✅ {label}에 대한 차단 규칙이 삭제되었습니다.")
                    with st.spinner("현재 규칙 새로고침 중..."):
                        st.code(fetch_iptables_rules(fw_host), language="text")
                else:
                    st.warning(
                        "규칙 삭제 중 오류가 발생했습니다. "
                        "해당 규칙이 이미 없거나 형식이 다를 수 있습니다."
                    )

    # ----------------------------------------------------------
    # 전체 초기화 섹션
    # ----------------------------------------------------------
    st.divider()
    st.subheader("🗑️ 전체 규칙 초기화 (iptables -F)")
    st.error(
        "⚠️ **위험:** INPUT/OUTPUT 체인의 **모든 규칙**이 삭제됩니다. "
        "실습 초기화 또는 응급 복구 용도로만 사용하십시오."
    )

    flush_check1 = st.checkbox(
        "전체 규칙 삭제의 영향을 충분히 이해했습니다.",
        key="flush_check1",
    )
    flush_check2 = st.checkbox(
        f"**{fw_host}** 서버의 모든 iptables 규칙을 삭제하는 것에 동의합니다.",
        key="flush_check2",
        disabled=not flush_check1,
    )

    if flush_check1 and flush_check2:
        if st.button("🗑️ 전체 규칙 삭제 실행", type="primary", key="btn_flush"):
            with st.spinner("전체 규칙 초기화 중..."):
                out = flush_iptables(fw_host)
            st.code(out, language="text")
            if "exit: 0" in out and "exit: -1" not in out:
                st.success(f"✅ {fw_host} 의 모든 iptables 규칙이 초기화되었습니다.")
                with st.spinner("현재 규칙 새로고침 중..."):
                    st.code(fetch_iptables_rules(fw_host), language="text")
            else:
                st.error("초기화 중 오류가 발생했습니다. 위 출력을 확인하세요.")
