# SecOps Automation Dashboard

A Streamlit-based security operations dashboard for phishing/smishing detection and automated firewall response. Built for university security lab training environments.

## Features

- **Text Analysis**: Score suspicious SMS/email content for phishing indicators using keyword and URL pattern matching
- **Remote Log Viewer**: SSH into target nodes to retrieve auth, syslog, and web server logs
- **Firewall Control**: Block and unblock IPs or domains via iptables, with DNS resolution for multi-IP domains
- **Rule Management**: View active iptables rules and flush chains for lab resets

## Architecture

```
┌─────────────────────────────┐
│  Control Center (128)        │
│  Streamlit Dashboard         │
│  • Text Analysis Engine      │
│  • SSH Command Dispatcher    │
└────────────┬────────────────┘
             │ SSH (password auth)
   ┌─────────┼──────────┐
   ▼         ▼          ▼
┌──────┐ ┌──────┐ ┌──────┐
│ 129  │ │ 130  │ │ 131  │
│ Sec  │ │ Web  │ │ SIEM │
└──────┘ └──────┘ └──────┘
```

## Setup

### 1. Clone and install

```bash
git clone https://github.com/greatbeats/SecOps-Automation-Dashboard.git
cd SecOps-Automation-Dashboard
pip install -r requirements.txt
```

### 2. Configure credentials

Set environment variables before running:

```bash
export SSH_USER="your_user"
export SERVER_PASS="your_password"
export SSH_PORT="22"
```

Or create `.streamlit/secrets.toml` (excluded from git via `.gitignore`):

```toml
SSH_USER = "your_user"
SERVER_PASS = "your_password"
SSH_PORT = "22"
```

### 3. Run

```bash
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```

Access at `http://<control-center-ip>:8501`

## Security Notes

- Credentials are loaded from environment variables or `st.secrets` — never hardcoded
- All firewall actions require explicit user confirmation before execution
- SSH uses `AutoAddPolicy` suitable for isolated lab environments only
- IPv6 addresses are filtered from DNS results (iptables IPv4 only)
