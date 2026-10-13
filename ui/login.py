"""Operator login screen."""
from __future__ import annotations

from html import escape

import streamlit as st

from ui.store import get_user_store
from ui.theme import CSS


def login_page():
    st.markdown(CSS, unsafe_allow_html=True)
    signal_rows = [
        "4F A2 01 7E", "REG_REQ", "0x1A2F > 0x00B4", "SUCI:123456", "AUTH_REQ",
        "91 0C 2D B8", "SEC_MODE_CMD", "IDENT_REQ", "0x00B4 > 0x1A2F", "GUTI_REALLOC",
        "7A 11 C0 4E", "REG_ACCEPT", "SUCI:130987", "5GMM: AUTHENTICATION", "D3 8F 22 01",
        "NAS: SECURITY_MODE", "0x2C10 > 0x008A", "IDENT_RESP", "5GMM: REGISTRATION",
        "8E 03 71 A5", "AUTH_RESP", "0x008A > 0x2C10", "5GS: ACCEPT", "C1 4B 90 6D",
        "GUTI_REALLOC", "5G NAS / N1", "22 E9 04 7B", "SEC_MODE_COMPLETE", "SUCI:482051",
        "0x1A2F > 0x00B4", "REG_REQ", "AF 38 0D 51", "5GMM: IDENTITY", "IDENT_REQ",
        "6C 02 B4 9A", "AUTH_REQ", "0x00B4 > 0x1A2F", "REG_ACCEPT", "5G NAS / N1",
    ]
    signal_columns = [
        ("2%", "43s", "-31s", ".13", "blue"), ("13%", "51s", "-17s", ".10", "blue"),
        ("24%", "36s", "-28s", ".16", "cyan"), ("35%", "48s", "-9s", ".11", "blue"),
        ("47%", "40s", "-34s", ".14", "blue"), ("59%", "54s", "-22s", ".09", "cyan"),
        ("70%", "33s", "-13s", ".17", "blue"), ("81%", "46s", "-39s", ".12", "blue"),
        ("92%", "38s", "-6s", ".15", "blue"),
    ]
    signal_text = "".join(f"<div>{row}</div>" for row in signal_rows)
    signal_markup = "".join(
        f'<div class="signal-column signal-{color}" style="--signal-left:{left};--signal-duration:{duration};--signal-delay:{delay};--signal-opacity:{opacity}">'
        f'<div class="signal-track">{signal_text}{signal_text}</div></div>'
        for left, duration, delay, opacity, color in signal_columns
    )
    st.markdown(
        f'<div class="terminal-signals" aria-hidden="true">'
        f'<div class="bg-grid"></div>'
        f'<span class="bg-orb orb-cyan"></span>'
        f'<span class="bg-orb orb-blue"></span>'
        f'<span class="bg-orb orb-violet"></span>'
        f'{signal_markup}<div class="signal-sweep"></div></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        """
        <style>
          @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');
          .stApp:has(.terminal-signals) { position:relative; isolation:isolate; background:radial-gradient(ellipse at 50% 0%, rgba(34,120,255,.2), transparent 60%),#030811 !important; }
          [data-testid="stAppViewContainer"] { position:relative; z-index:0; background:transparent !important; }
          section[data-testid="stMain"], [data-testid="stMainBlockContainer"] { background:transparent !important; }
          [data-testid="stMainBlockContainer"] > [data-testid="stVerticalBlock"] { position:relative; z-index:1; background:transparent !important; }
          [data-testid="stHeader"], [data-testid="stToolbar"] { display:none !important; }
          section[data-testid="stSidebar"] { display:none !important; }
          .terminal-signals { position:fixed; inset:0; z-index:-1; overflow:hidden; pointer-events:none; }
          .terminal-signals:after { content:"";position:absolute;inset:0;background:repeating-linear-gradient(to bottom,transparent 0,transparent 2px,rgba(0,5,13,.22) 3px);pointer-events:none; }
          .signal-column { position:absolute;left:var(--signal-left);top:0;height:100%;overflow:hidden;white-space:nowrap;color:#2A6FD0;opacity:var(--signal-opacity);font:400 11px/16px 'JetBrains Mono',monospace;letter-spacing:.015em; }
          .signal-cyan { color:#22D3EE; }
          .signal-track { animation:signal-scroll var(--signal-duration) linear var(--signal-delay) infinite;will-change:transform; }
          .signal-track > div { height:16px; }
          @keyframes signal-scroll { from { transform:translateY(0); } to { transform:translateY(-50%); } }
          .signal-sweep { position:absolute;left:0;right:0;top:-18vh;height:18vh;background:linear-gradient(to bottom,transparent,rgba(30,106,201,.055),rgba(48,139,228,.075),transparent);opacity:.5;animation:signal-sweep 9s linear infinite; }
          @keyframes signal-sweep { from { transform:translateY(0);opacity:0; } 10% {opacity:.55;} 90% {opacity:.45;} to { transform:translateY(125vh);opacity:0; } }
          .bg-grid { position:absolute; inset:-2px; background-image:
              linear-gradient(rgba(24,110,190,.16) 1px, transparent 1px),
              linear-gradient(90deg, rgba(24,110,190,.16) 1px, transparent 1px);
              background-size: 56px 56px;
              -webkit-mask-image: radial-gradient(ellipse at 50% 30%, #000 30%, transparent 78%);
              mask-image: radial-gradient(ellipse at 50% 30%, #000 30%, transparent 78%);
              animation: grid-drift 16s linear infinite; }
          @keyframes grid-drift { from { background-position: 0 0; } to { background-position: 112px 112px; } }
          .bg-orb { position:absolute; border-radius:50%; filter:blur(72px); opacity:.4; will-change:transform; pointer-events:none; }
          .orb-cyan { width:480px; height:480px; left:-140px; top:-160px; background:radial-gradient(circle, rgba(18,212,232,.5), transparent 68%); animation:orb-drift-1 26s ease-in-out infinite alternate; }
          .orb-blue { width:420px; height:420px; right:-120px; bottom:-140px; background:radial-gradient(circle, rgba(34,150,255,.42), transparent 68%); animation:orb-drift-2 32s ease-in-out infinite alternate; }
          .orb-violet { width:320px; height:320px; left:46%; top:55%; background:radial-gradient(circle, rgba(130,90,255,.28), transparent 68%); animation:orb-drift-3 24s ease-in-out infinite alternate; }
          @keyframes orb-drift-1 { from{transform:translate(0,0) scale(1);} to{transform:translate(70px,52px) scale(1.18);} }
          @keyframes orb-drift-2 { from{transform:translate(0,0) scale(1);} to{transform:translate(-60px,-46px) scale(1.14);} }
          @keyframes orb-drift-3 { from{transform:translate(0,0) scale(1);} to{transform:translate(-44px,34px) scale(1.22);} }
          @media(prefers-reduced-motion:reduce) { .signal-track,.signal-sweep,.bg-grid,.bg-orb { animation:none!important;will-change:auto; } }
          .stAppViewContainer [data-testid="stMainBlockContainer"] { max-width:none!important;padding:48px 16px!important; }
          .stAppViewContainer [data-testid="stMainBlockContainer"] > [data-testid="stVerticalBlock"] { gap:0!important; }
          div.st-key-auth-terminal { position:relative!important;flex:0 0 auto!important;gap:0!important;box-sizing:border-box!important;width:100%;max-width:1060px;height:min(calc(100vh - 96px), 780px)!important;min-height:520px!important;margin:0 auto!important;padding:43px 0 30px!important;overflow:hidden;background:rgba(5,14,27,.9)!important;border:1px solid #14407A!important;border-radius:12px!important;box-shadow:0 0 80px rgba(34,120,255,.28); }
          div.st-key-auth-terminal:after { content:"";position:absolute;z-index:2;top:44px;bottom:30px;left:calc(50% + 40px);width:1px;background:#163451;pointer-events:none; }
          div.st-key-auth-terminal > [data-testid="stVerticalBlock"] { position:static!important;height:100%!important;min-height:0;display:flex;flex-direction:column;gap:0!important; }
          div.st-key-auth-terminal > [data-testid="stElementContainer"]:first-child { position:absolute!important;top:0!important;left:0!important;right:0!important;height:43px!important;z-index:4!important; }
          div.st-key-auth-terminal > [data-testid="stElementContainer"]:last-child { position:absolute!important;bottom:0!important;left:0!important;right:0!important;height:30px!important;z-index:4!important; }
          div.st-key-auth-terminal [data-testid="stLayoutWrapper"] { flex:1 1 auto!important;min-height:0!important;height:auto!important;overflow:hidden!important; }
          .terminal-chrome { min-height:43px;box-sizing:border-box;display:flex;align-items:center;gap:8px;padding:12px 16px;background:#08172C;border-bottom:1px solid #14407A;color:#6F93BF;font:12px 'JetBrains Mono',monospace; }
          .chrome-dot { width:11px;height:11px;border-radius:50%;flex:none;background:#3B9EFF; }
          .chrome-dot:nth-child(2) { background:#1D5FB8; }.chrome-dot:nth-child(3) { background:#123A6B; }
          .chrome-title { flex:1;text-align:center; }.chrome-status { display:flex;align-items:center;gap:7px;color:#22D3EE;white-space:nowrap; }
          .chrome-status i { width:8px;height:8px;border-radius:50%;background:#22D3EE;display:inline-block; }
          div.st-key-auth-terminal [data-testid="stHorizontalBlock"] { position:static!important;z-index:2;top:auto!important;left:auto!important;right:auto!important;bottom:auto!important;transform:none!important;width:100%!important;height:auto!important;flex:1!important;min-height:0!important;gap:0!important;flex-direction:row!important;flex-wrap:nowrap!important;align-items:stretch!important;overflow:hidden!important; }
          div.st-key-auth-terminal [data-testid="stColumn"] { height:100%!important;min-width:0!important;box-sizing:border-box;padding:0!important;overflow:hidden!important; }
          div.st-key-auth-terminal [data-testid="stColumn"] > [data-testid="stVerticalBlock"] { box-sizing:border-box;height:100%!important;min-height:0!important;padding:24px 32px 26px!important;overflow-y:auto!important; }
          div.st-key-auth-terminal [data-testid="stColumn"]:first-child { border-right:1px solid #0F2B52; }
          div.st-key-auth-terminal [data-testid="stColumn"]:first-child > [data-testid="stVerticalBlock"] { position:relative!important;padding:0!important;overflow:hidden!important; }
          div.st-key-auth-terminal [data-testid="stColumn"]:first-child [data-testid="stElementContainer"] { position:static!important; }
          .terminal-pane { position:absolute!important;inset:0!important;margin:0!important;height:auto!important;min-height:0;box-sizing:border-box;padding:24px 32px 26px!important;display:flex;flex-direction:column;color:#D0E1F5;font:12.5px/1.75 'JetBrains Mono',monospace; }
          .naswatch-ascii { margin:0 0 6px;max-width:100%;overflow-x:auto;white-space:pre;flex:none;font:700 clamp(9px,1.32vw,15px)/1.35 'JetBrains Mono',Consolas,monospace;color:#7CC5FF;text-shadow:0 0 7px rgba(59,158,255,.6);letter-spacing:.2px; }
          .naswatch-word { display:none;flex:none;margin:2px 0 10px;font:800 clamp(26px,6.5vw,40px)/1.05 'JetBrains Mono',Consolas,monospace;letter-spacing:4px;color:#7CC5FF;text-shadow:0 0 14px rgba(59,158,255,.55); }
          .terminal-subtitle { color:#6F93BF;margin-bottom:18px;flex:none; }
          .stream-heading { display:flex;justify-content:space-between;color:#6F93BF;font-size:11px;letter-spacing:1px;padding-bottom:6px;border-bottom:1px dashed #14407A;margin:0 0 8px;flex:none; }
          .event-stream { flex:1 1 auto;min-height:56px;height:auto!important;overflow:hidden;white-space:nowrap;-webkit-mask-image:linear-gradient(180deg,transparent,#000 14%,#000 86%,transparent);mask-image:linear-gradient(180deg,transparent,#000 14%,#000 86%,transparent); }
          .feed { animation:feed 26s linear infinite; }
          @keyframes feed { from { transform:translateY(0); } to { transform:translateY(-50%); } }
          .event-row { height:24px; }.event-time { color:#4E7099; }.event-info { color:#22D3EE; }.event-warn { color:#3B9EFF; }.event-alert { color:#F5B942;font-weight:700; }
          .terminal-prompt { flex:none;margin-top:10px;color:#22D3EE; }.terminal-prompt span { color:#B9CDE5; }
          .cur { display:inline-block;width:8px;height:15px;background:#22D3EE;vertical-align:middle;margin-left:6px;animation:blink 1s steps(1) infinite; }
          .dot-pulse { animation:pulse 2s ease-out infinite; }
          @keyframes blink { 0%,49%{opacity:1}50%,100%{opacity:0} }
          @keyframes pulse { 0%,100%{box-shadow:0 0 0 0 rgba(34,211,238,.6)}50%{box-shadow:0 0 0 6px rgba(34,211,238,0)} }
          .auth-heading { color:#22D3EE;font-size:12px;letter-spacing:1px;margin:30px 32px 6px 38px; }
          .auth-copy { color:#6F93BF;margin:0 32px 6px 38px;font-size:12.5px; }
          div.st-key-auth-terminal .stForm { width:calc(100% - 70px)!important;margin:0 32px 0 38px;background:transparent!important;border:0!important;border-radius:0!important;padding:0!important; }
          div.st-key-auth-terminal .stTextInput { margin-bottom:0!important; }
          div.st-key-auth-terminal .stTextInput label { color:#58A9FF!important;font:700 12px 'JetBrains Mono',monospace!important;letter-spacing:0!important;text-transform:none!important;margin-bottom:2px!important; }
          div.st-key-auth-terminal .stTextInput input { box-sizing:border-box;height:44px!important;padding:0 14px!important;background:#030B16!important;border:1px solid #1D4F8F!important;border-radius:6px!important;color:#D6E8FF!important;font:14px 'JetBrains Mono',monospace!important; }
          div.st-key-auth-terminal .stTextInput input::placeholder { color:#4E7099!important; }
          div.st-key-auth-terminal .stTextInput input:focus { outline:none!important;border-color:#22D3EE!important;box-shadow:0 0 0 3px rgba(34,211,238,.15)!important; }
          div.st-key-auth-terminal button:not([kind="primary"]) { background:#0B1B30!important;border:1px solid #28517D!important;border-radius:6px!important;color:#B9CDE5!important; }
          div.st-key-auth-terminal .stTextInput button { height:44px!important; }
          div.st-key-auth-terminal .stFormSubmitButton button { width:100%;height:48px;border-radius:6px!important;background:#0F55C8!important;border:1px solid #5CB8FF!important;color:#fff!important;font:700 14px 'JetBrains Mono',monospace!important;letter-spacing:1.5px!important; }
          div.st-key-auth-terminal .stFormSubmitButton button:hover { background:#1668E8!important;box-shadow:0 0 24px rgba(59,158,255,.35); }
          .demo-users { margin:8px 32px 0 38px;padding:8px 12px;border:1px dashed #14407A;border-radius:6px;background:#040C18;color:#E2EDFA;font:12px/1.5 'JetBrains Mono',monospace; }
          .demo-heading { color:#6F93BF;margin-bottom:7px; }.demo-row { display:flex;justify-content:space-between;flex-wrap:wrap;gap:4px; }.demo-role { color:#3B9EFF; }
          .terminal-footer { position:static!important;z-index:3;left:auto!important;transform:none!important;bottom:auto!important;width:100%!important;flex:none!important;height:30px;min-height:30px;box-sizing:border-box;display:flex;align-items:center;justify-content:space-between;flex-wrap:nowrap;gap:8px;padding:0 16px;background:#0A3A7A;color:#F0F6FF;font:11px/1.4 'JetBrains Mono',monospace;white-space:nowrap;border-top:1px solid #2462A9;margin-top:auto!important; }
          .terminal-pane,.auth-heading,.auth-copy,.demo-users,.terminal-footer,.terminal-chrome { text-shadow:0 1px 1px rgba(0,0,0,.55); }
          @media(max-width:760px){.stAppViewContainer [data-testid="stMainBlockContainer"]{padding:20px 8px!important;margin-top:0!important}div.st-key-auth-terminal{height:min(calc(100vh - 40px), 720px)!important;min-height:420px!important;max-width:100%!important}div.st-key-auth-terminal:after{display:none}div.st-key-auth-terminal [data-testid="stHorizontalBlock"]{flex-direction:row!important;flex-wrap:nowrap!important}div.st-key-auth-terminal [data-testid="stColumn"] > [data-testid="stVerticalBlock"]{padding:16px 16px 18px!important}div.st-key-auth-terminal [data-testid="stColumn"]:first-child{border-right:1px solid #0F2B52;border-bottom:0}.naswatch-ascii{display:none!important}.naswatch-word{display:block!important}.terminal-pane{padding:16px 16px 18px!important}.terminal-subtitle{font-size:11px;margin-bottom:12px}.stream-heading{font-size:10px}.event-stream{min-height:40px}.auth-heading{margin:16px 0 6px!important}.auth-copy{margin:0 0 6px!important}div.st-key-auth-terminal .stForm{width:auto!important;margin:0!important}.demo-users{margin:8px 0 0!important}}
        </style>
        """,
        unsafe_allow_html=True,
    )
    events = [
        ("09:41:02", "INFO", "UE registration accepted"),
        ("09:41:05", "WARN", "repeated Identity Request"),
        ("09:41:08", "ALERT", "NAS replay suspected"),
        ("09:41:11", "INFO", "security mode complete"),
        ("09:41:14", "WARN", "null cipher (NEA0) requested"),
        ("09:41:17", "ALERT", "rogue gNB signature matched"),
        ("09:41:20", "INFO", "PDU session established"),
        ("09:41:23", "WARN", "SUCI concealment disabled"),
        ("09:41:26", "INFO", "authentication vector verified"),
        ("09:41:29", "ALERT", "downgrade attempt blocked"),
        ("09:41:32", "INFO", "GUTI reallocation complete"),
        ("09:41:35", "WARN", "abnormal detach rate on cell"),
    ]
    event_class = {"INFO": "event-info", "WARN": "event-warn", "ALERT": "event-alert"}
    rows = "".join(
        f'<div class="event-row"><span class="event-time">{timestamp}</span> '
        f'<span class="{event_class[level]}">{level}</span>&nbsp; {message}</div>'
        for timestamp, level, message in events
    )
    events_html = f'<div class="feed">{rows}{rows}</div>'
    ascii_art = "\n".join([
        r" _   _    _    ____ __        __      _       _     ",
        r"| \ | |  / \  / ___|\ \      / /__ _| |_ ___| |__  ",
        r"|  \| | / _ \ \___ \ \ \ /\ / / _` | __/ __| '_ \ ",
        r"| |\  |/ ___ \ ___) | \ V  V / (_| | || (__| | | |",
        r"|_| \_/_/   \_\____/   \_/\_/ \__,_|\__\___|_| |_|",
    ])
    with st.container(key="auth-terminal", border=False):
        st.markdown(
            '<div class="terminal-chrome"><i class="chrome-dot"></i><i class="chrome-dot"></i>'
            '<i class="chrome-dot"></i><span class="chrome-title">naswatch@soc-01: ~ — auth</span>'
            '<span class="chrome-status"><i class="dot-pulse"></i>SENSOR ONLINE</span></div>',
            unsafe_allow_html=True,
        )
        left, right = st.columns([1.15, 1], gap="small", vertical_alignment="top")
        with left:
            st.markdown(
                f'<div class="terminal-pane"><div class="naswatch-ascii">{escape(ascii_art)}</div>'
                '<div class="naswatch-word">NASWatch</div>'
                '<div class="terminal-subtitle">5G control-plane security // blue team console</div>'
                '<div class="stream-heading"><span>$ tail -f nas-events.log</span><span>SAMPLE STREAM</span></div>'
                f'<div class="event-stream">{events_html}</div>'
                '<div class="terminal-prompt">$ <span>awaiting operator login</span>'
                '<span class="cur"></span></div></div>',
                unsafe_allow_html=True,
            )
        with right:
            st.markdown(
                '<div class="auth-heading">[ OPERATOR AUTHENTICATION ]</div>'
                '<div class="auth-copy">Sign in to open the security console.</div>',
                unsafe_allow_html=True,
            )
            with st.form("operator_login", clear_on_submit=False):
                username = st.text_input("> login", value="admin@naswatch.io", autocomplete="username")
                password = st.text_input(
                    "> password",
                    type="password",
                    placeholder="********",
                    autocomplete="current-password",
                    key="login_password",
                )
                submitted = st.form_submit_button("> AUTHENTICATE", use_container_width=True, type="primary")
            if submitted:
                if not username or not password:
                    st.error("Enter your email and password to continue.")
                else:
                    store = get_user_store()
                    if store is None:
                        st.error("Authentication service is unavailable. Please try again shortly.")
                    else:
                        user = store.authenticate(username, password)
                        if user is None:
                            st.error("We couldn't sign you in with those credentials.")
                        else:
                            st.session_state["user"] = {
                                "id": user.id, "username": user.username,
                                "role": user.role.value, "org_id": user.org_id,
                            }
                            # Persist the session so a refresh keeps the operator signed in.
                            st.session_state["_persist_session"] = True
                            st.rerun()
            st.markdown(
                '<div class="demo-users"><div class="demo-heading"><span style="color:#22D3EE">$</span> cat demo_users</div>'
                '<div class="demo-row"><span>admin@naswatch.io</span><span class="demo-role">admin</span></div>'
                '<div class="demo-row"><span>analyst@naswatch.io</span><span class="demo-role">analyst</span></div>'
                '<div class="demo-row"><span>viewer@naswatch.io</span><span class="demo-role">viewer</span></div></div>',
                unsafe_allow_html=True,
            )
        st.markdown(
            '<div class="terminal-footer"><span>[0] auth*</span><span>session: unauthenticated</span><span>NASWatch</span></div>',
            unsafe_allow_html=True,
        )
