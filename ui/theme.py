"""NASWatch SOC theme CSS (matches naswatch_redesign.html)."""

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root{
  --bg-base:#030A14; --bg-panel:#061226; --bg-raised:#0A1B35; --bg-input:#030D1B;
  --border:#174A83; --border-soft:#102E50;
  --text-1:#D6E7FA; --text-2:#8CAED3; --text-3:#5F83AA;
  --signal:#12D4E8; --signal-dim:#13547B;
  --crit:#FF466B; --high:#FFB82F; --med:#4CA8FF; --low:#11D9ED;
  --mono:'IBM Plex Mono', ui-monospace, monospace;
  --sans:'IBM Plex Sans', system-ui, sans-serif;
}

html, body, [class*="css"] { font-family: var(--sans) !important; color: var(--text-1); }
code, pre, [class*="code"], .stCode { font-family: var(--mono) !important; }
.stApp { background: var(--bg-base) !important; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
  background: var(--bg-panel) !important;
  border-right: 1px solid var(--border-soft) !important;
  padding-top: 0 !important;
}
section[data-testid="stSidebar"] .stMarkdown { color: var(--text-2); }
section[data-testid="stSidebar"] .stMarkdown h3,
section[data-testid="stSidebar"] .stMarkdown h4,
section[data-testid="stSidebar"] .stMarkdown h5 {
  color: var(--text-3) !important; font-size: 10px !important; font-weight: 600 !important;
  letter-spacing: 0.06em !important; text-transform: uppercase !important; margin-bottom: 6px !important;
}

/* ── Sidebar nav links — styled as .navlink from redesign ── */
[data-testid="stSidebar"] .stRadio { margin-bottom: 0; }
[data-testid="stSidebar"] .stRadio > div { gap: 0 !important; }
[data-testid="stSidebar"] .stRadio > div > label {
  display: flex !important; align-items: center; gap: 10px;
  padding: 9px 10px !important; border-radius: 4px;
  color: var(--text-2) !important; font-size: 13.5px !important; font-weight: 500 !important;
  border-left: 2px solid transparent; margin-bottom: 2px;
  background: transparent !important;
  transition: all 0.12s ease;
}
[data-testid="stSidebar"] .stRadio > div > label:hover {
  color: var(--text-1) !important; background: var(--bg-raised) !important;
}
[data-testid="stSidebar"] .stRadio > div > label:has(input:checked) {
  color: var(--text-1) !important; background: var(--bg-raised) !important;
  border-left-color: var(--signal) !important; font-weight: 600 !important;
}
[data-testid="stSidebar"] .stRadio > div > label {
  border-radius: 7px; padding: 10px 12px !important; margin: 2px 0;
}
[data-testid="stSidebar"] .stRadio > div > label:has(input:checked) {
  box-shadow: inset 0 0 0 1px rgba(79,209,197,.10);
}
/* hide the default radio circle */
[data-testid="stSidebar"] .stRadio > div > label > span:first-child {
  display: none !important;
}

/* ── Inputs ── */
.stTextInput input, .stSelectbox select, .stMultiSelect [data-baseweb="select"] {
  background: var(--bg-input) !important;
  border: 1px solid var(--border-soft) !important;
  color: var(--text-1) !important;
  border-radius: 3px !important;
  font-family: var(--mono) !important;
  font-size: 12px !important;
}
.stTextInput input:focus, .stSelectbox select:focus {
  border-color: var(--border) !important;
}
.stTextInput label, .stSelectbox label, .stMultiSelect label {
  color: var(--text-3) !important; font-size: 10px !important; font-weight: 600 !important;
  letter-spacing: 0.05em !important; text-transform: uppercase !important;
}

/* ── Buttons — red replay, green deploy ── */
.stButton > button {
  background: transparent !important;
  border: 1px solid var(--border) !important;
  color: var(--text-1) !important;
  border-radius: 3px !important;
  font-weight: 600 !important;
  font-size: 12px !important;
  font-family: var(--sans) !important;
  transition: all 0.12s ease;
}
.stButton > button:hover { border-color: var(--text-3) !important; background: var(--bg-raised) !important; }
.stButton > button[kind="primary"] {
  background: var(--crit) !important; border-color: var(--crit) !important; color: #fff !important;
}
.stButton > button[kind="primary"]:hover { background: #c93c40 !important; }
.btn-deploy {
  background: var(--signal) !important; border: none !important;
  color: #06110C !important; font-weight: 600 !important; font-size: 12.5px !important;
  padding: 8px 15px !important; border-radius: 3px !important;
}

/* ── Expanders ── */
details[data-testid="stExpander"] {
  background: var(--bg-panel) !important; border: 1px solid var(--border-soft) !important; border-radius: 4px !important;
}
details[data-testid="stExpander"] summary { color: var(--text-1) !important; font-weight: 500 !important; }

/* ── DataFrames ── */
.stDataFrame { border: 1px solid var(--border-soft) !important; border-radius: 4px !important; }

/* ── Forms ── */
.stForm { background: var(--bg-panel) !important; border: 1px solid var(--border-soft) !important; border-radius: 4px !important; }

/* ── Divider ── */
hr { border-color: var(--border-soft) !important; }

/* ── Toast ── */
.stToast { background: var(--bg-panel) !important; border: 1px solid var(--border-soft) !important; }

/* ── Download ── */
.stDownloadButton > button {
  background: var(--bg-raised) !important; border: 1px solid var(--border) !important; color: var(--text-1) !important;
}
.stDownloadButton > button:hover { border-color: var(--text-3) !important; }

/* ══════════════════════════════════════════════════════════════════════════════ */
/*  COMPONENTS — matching naswatch_redesign.html                               */
/* ══════════════════════════════════════════════════════════════════════════════ */

/* ── KPI strip ── */
.kpi-strip {
  border: 1px solid var(--border-soft); border-radius: 4px; display: grid;
  grid-template-columns: repeat(5, 1fr); background: var(--bg-panel); margin-bottom: 24px;
}
.kpi { padding: 16px 20px; border-right: 1px solid var(--border-soft); }
.kpi:last-child { border-right: none; }
.kpi-label { color: var(--text-3); font-size: 10.5px; font-weight: 600; letter-spacing: 0.04em; margin-bottom: 8px; }
.kpi-value { font-family: var(--mono); font-size: 27px; font-weight: 500; line-height: 1; }
.kpi-detail { color: var(--text-3); font-size: 11.5px; margin-top: 7px; }
.kpi.c-signal { box-shadow: inset 2px 0 0 var(--signal); }
.kpi.c-signal .kpi-value { color: var(--text-1); }
.kpi.c-alert { box-shadow: inset 2px 0 0 var(--text-2); }
.kpi.c-alert .kpi-value { color: var(--text-1); }
.kpi.c-crit { box-shadow: inset 2px 0 0 var(--crit); }
.kpi.c-crit .kpi-value { color: var(--crit); }
.kpi.c-high { box-shadow: inset 2px 0 0 var(--high); }
.kpi.c-high .kpi-value { color: var(--high); }
.kpi.c-low { box-shadow: inset 2px 0 0 var(--low); }
.kpi.c-low .kpi-value { color: var(--low); }

/* ── Grid ── */
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }

/* ── Section card ── */
.section-card {
  border: 1px solid var(--border-soft); border-radius: 4px; padding: 20px;
  background: var(--bg-panel);
}
.section-card h3 { margin: 0 0 18px; font-size: 13px; font-weight: 600; }

/* ── Page layout ── */
.page-title { font-size: 20px; font-weight: 700; letter-spacing: -0.01em; margin: 0 0 5px; }
.page-sub { color: var(--text-2); font-size: 13px; max-width: 560px; line-height: 1.5; }
.page-head { display: flex; align-items: flex-end; justify-content: space-between; margin-bottom: 22px; flex-wrap: wrap; gap: 14px; }
.page-stats { display: flex; gap: 22px; }
.pstat { text-align: right; }
.pstat-val { font-family: var(--mono); font-size: 20px; font-weight: 500; }
.pstat-label { color: var(--text-3); font-size: 10.5px; font-weight: 600; letter-spacing: 0.04em; margin-top: 2px; }

/* ── Severity tags ── */
.sev-tag {
  font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.04em;
  padding: 3px 7px; border-radius: 2px; flex-shrink: 0;
}
.sev-critical { color: var(--crit); border: 1px solid var(--crit); }
.sev-high { color: var(--high); border: 1px solid var(--high); }
.sev-medium { color: var(--med); border: 1px solid var(--med); }
.sev-low { color: var(--low); border: 1px solid var(--low); }

/* ── Slice table ── */
.slice-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.slice-table th {
  text-align: left; color: var(--text-3); font-size: 10.5px; font-weight: 600;
  letter-spacing: 0.04em; padding: 9px 14px; border-bottom: 1px solid var(--border); background: var(--bg-raised);
}
.slice-table td { padding: 11px 14px; border-bottom: 1px solid var(--border-soft); color: var(--text-2); }
.slice-swatch { width: 8px; height: 8px; border-radius: 2px; display: inline-block; margin-right: 8px; }

/* ── Compliance grid ── */
.compliance-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
.compliance-card {
  border: 1px solid var(--border-soft); border-radius: 4px; padding: 19px 17px; background: var(--bg-panel);
}
.compliance-card .code { font-family: var(--mono); font-size: 13.5px; font-weight: 600; }
.compliance-card .desc { color: var(--text-3); font-size: 11.5px; margin: 5px 0 13px; }
.compliant-tag {
  color: var(--signal); font-size: 10.5px; font-weight: 600; letter-spacing: 0.04em;
  border: 1px solid var(--signal-dim); padding: 3px 8px; border-radius: 2px; display: inline-block;
}

/* ── Audit log ── */
.audit-log { border: 1px solid var(--border-soft); border-radius: 4px; background: var(--bg-panel); padding: 4px 0; margin-bottom: 20px; }
.audit-row {
  display: flex; align-items: center; gap: 14px; padding: 11px 18px;
  border-bottom: 1px solid var(--border-soft); font-size: 12.5px;
}
.audit-row:last-child { border-bottom: none; }
.audit-row time { font-family: var(--mono); color: var(--text-3); font-size: 11.5px; width: 150px; flex-shrink: 0; }
.audit-row .actor { color: var(--text-1); font-weight: 500; }
.audit-row .act { color: var(--text-2); }

/* ── Sidebar blocks ── */
.sidebar-block {
  background: var(--bg-raised); border: 1px solid var(--border-soft); border-radius: 4px;
  padding: 13px; margin-bottom: 14px;
}
.live-tag { display: flex; align-items: center; gap: 7px; color: var(--signal); font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; margin-bottom: 9px; }
.pulse-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--signal); box-shadow: 0 0 0 3px rgba(18,212,232,0.14); flex-shrink: 0; }
.live-port { font-family: var(--mono); font-size: 18px; font-weight: 500; color: var(--text-1); }
.live-sub { color: var(--text-3); font-size: 11.5px; margin-top: 3px; }

.sidebar-heading { display: flex; align-items: center; gap: 7px; color: var(--text-2); font-size: 12px; font-weight: 600; margin-bottom: 9px; }
.pcap-path {
  background: var(--bg-input); border: 1px solid var(--border-soft); border-radius: 3px;
  padding: 8px 9px; font-family: var(--mono); font-size: 11.5px; color: var(--text-2);
  margin-bottom: 9px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.btn-replay {
  width: 100%; background: transparent; border: 1px solid var(--crit); color: var(--crit);
  font-weight: 600; font-size: 12.5px; padding: 9px; border-radius: 3px; cursor: pointer;
}
.btn-replay:hover { background: rgba(229,72,77,0.08); }

.sidebar-footer {
  margin-top: auto; padding-top: 14px; border-top: 1px solid var(--border-soft);
  display: flex; align-items: center; gap: 9px; color: var(--text-3); font-size: 11.5px;
}
.sidebar-footer .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--signal); }

/* ── Incident cards ── */
.incident { border: 1px solid var(--border-soft); border-radius: 4px; background: var(--bg-panel); overflow: hidden; margin-bottom: 9px; }
.incident-head { display: flex; align-items: center; gap: 11px; padding: 13px 16px; cursor: pointer; }
.incident-head .chevr { margin-left: auto; color: var(--text-3); font-size: 12px; transition: transform 0.15s; }
.incident.open .incident-head .chevr { transform: rotate(90deg); }
.incident-title { font-size: 13px; color: var(--text-1); font-weight: 500; }
.incident-time { color: var(--text-3); font-size: 11.5px; font-family: var(--mono); margin-left: 10px; }
.incident-body { max-height: 0; overflow: hidden; transition: max-height 0.22s ease; border-top: 1px solid var(--border-soft); }
.incident.open .incident-body { max-height: 320px; }
.incident-body-inner { padding: 16px 20px; display: grid; grid-template-columns: 1.3fr 1fr; gap: 24px; }
.incident-desc { color: var(--text-2); font-size: 12.5px; line-height: 1.6; }
.field-table { width: 100%; border-collapse: collapse; margin-top: 14px; font-size: 12px; }
.field-table td { padding: 7px 0; border-bottom: 1px solid var(--border-soft); }
.field-table td:first-child { color: var(--text-3); font-weight: 600; width: 70px; }
.field-table td:last-child { font-family: var(--mono); color: var(--signal); }
.soar-btns { display: flex; gap: 8px; margin-bottom: 10px; }
.soar-btn { flex: 1; border: 1px solid var(--border); background: var(--bg-input); color: var(--text-1); font-size: 12px; font-weight: 600; padding: 8px; border-radius: 3px; cursor: pointer; }
.soar-btn.revoke { color: var(--crit); border-color: rgba(229,72,77,0.35); }
.soar-btn.quarantine { color: var(--high); border-color: rgba(245,165,36,0.35); }
.triage-select { width: 100%; background: var(--bg-input); border: 1px solid var(--border-soft); color: var(--text-1); font-size: 12px; font-weight: 600; padding: 8px 10px; border-radius: 3px; }

/* ── NASWatch console design system ── */
.stApp {
  background: radial-gradient(ellipse at 85% -15%, rgba(50,91,137,.14), transparent 42%), var(--bg-base) !important;
}
[data-testid="stSidebar"] .nav-section-label {
  margin:8px 0 4px !important; padding:4px 10px 5px !important; color:#527BA5 !important;
  font:700 9px var(--mono) !important; letter-spacing:.15em !important; border-bottom:1px solid #102B49;
}
[data-testid="stMainBlockContainer"] { max-width: 1560px; padding-top: 0.5rem; }
section[data-testid="stSidebar"] { box-shadow: 10px 0 35px rgba(0,0,0,.12); }
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: .55rem; }
.kpi-strip {
  border-color: var(--border-soft); border-radius: 10px; overflow: hidden;
  box-shadow: 0 12px 32px rgba(0,0,0,.14); margin-bottom: 25px;
}
.kpi { padding: 19px 21px; }
.kpi-label { color: #91A0B7; letter-spacing: .075em; }
.kpi-value { font-size: 29px; letter-spacing: -.04em; }
.kpi-detail { color: #7D8AA0; }
.section-card, .compliance-card, .sidebar-block, .audit-log,
details[data-testid="stExpander"], .stForm {
  border-color: var(--border-soft) !important; border-radius: 10px !important;
  box-shadow: 0 10px 28px rgba(0,0,0,.12);
}
.section-card { padding: 22px; }
.section-card h3 { font-size: 14px; letter-spacing: -.01em; margin-bottom: 20px; }
.page-head { margin-bottom: 26px; }
.page-title { font-size: 25px; letter-spacing: -.035em; }
.page-sub { max-width: 680px; color: #9AA8BC; font-size: 13.5px; }
.topbar {
  display:flex; align-items:center; justify-content:space-between; padding:15px 32px;
  border-bottom:1px solid var(--border-soft); background:rgba(11,16,32,.78);
  backdrop-filter:blur(14px); position:sticky; top:0; z-index:100;
}
.topbar-crumb { color:var(--text-2); font-size:13px; }
.topbar-crumb strong { color:var(--text-1); font-weight:600; }
.topbar-meta { display:flex; align-items:center; gap:14px; }
.console-badge { display:flex; align-items:center; gap:8px; padding:7px 11px; border:1px solid var(--signal-dim); border-radius:99px; color:var(--signal); font-size:10px; font-weight:700; letter-spacing:.07em; }
.nav-section-label { color:var(--text-3); font-size:9px; font-weight:700; letter-spacing:.12em; padding:4px 10px 1px; }
.filter-chips { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:18px; }
.scope-bar { display:flex; align-items:center; gap:10px; padding:10px 14px; margin:14px 0 0; border:1px solid var(--border-soft); border-radius:9px; background:rgba(17,24,39,.72); }
.scope-label { color:var(--text-3); font-size:10px; font-weight:700; letter-spacing:.1em; }
.queue-heading { display:flex; align-items:center; justify-content:space-between; margin:27px 0 12px; }
.queue-heading h3 { margin:0; font-size:15px; }
.queue-heading span { color:var(--text-3); font-size:11px; }
.severity-pill { display:inline-block; border:1px solid currentColor; border-radius:99px; padding:3px 8px; font-size:10px; font-weight:700; letter-spacing:.04em; }
.pstat-val { font-size: 22px; letter-spacing: -.03em; }
.pstat-label { letter-spacing: .075em; }
.compliance-card { padding: 22px; }
.incident, .stDataFrame, [data-testid="stTable"] { border-radius: 9px !important; }
.incident { border-color: var(--border-soft); box-shadow: 0 8px 22px rgba(0,0,0,.10); }
.incident-head { padding: 15px 18px; }
.audit-row { padding: 13px 18px; }
.slice-table th { padding: 12px 14px; text-transform: uppercase; letter-spacing: .07em; }
.slice-table td { padding: 13px 14px; }
.stButton > button, .stDownloadButton > button {
  min-height: 40px; border-radius: 7px !important; border-color: var(--border) !important;
}
.stButton > button:hover, .stDownloadButton > button:hover {
  transform: translateY(-1px); border-color: var(--signal) !important;
  box-shadow: 0 5px 16px rgba(0,0,0,.18);
}
.stButton > button[kind="primary"] { border-radius: 7px !important; }
.stTextInput input, .stSelectbox [data-baseweb="select"], .stMultiSelect [data-baseweb="select"] {
  border-radius: 7px !important; min-height: 40px;
}
details[data-testid="stExpander"] summary { padding-top: 3px; padding-bottom: 3px; }
div[data-testid="stMetric"] { background: var(--bg-panel); border: 1px solid var(--border-soft); border-radius: 9px; padding: 16px; }

/* ── Responsive layout and keyboard focus ── */
.stApp { min-width: 320px; }
:focus-visible { outline: 2px solid var(--signal) !important; outline-offset: 2px; }
.stDataFrame, [data-testid="stTable"] { overflow-x: auto; }
@media (max-width: 900px) {
  .kpi-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .kpi:nth-child(3) { border-right: 0; }
  .kpi:nth-child(n+4) { border-top: 1px solid var(--border-soft); }
  .compliance-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .grid-2 { grid-template-columns: 1fr; }
}
@media (max-width: 600px) {
  [data-testid="stMainBlockContainer"] { padding: 0.75rem 1rem 2rem !important; }
  div[style*="padding:28px 32px 70px"] { padding: 20px 0 48px !important; }
  .topbar { padding: 12px 16px; }
  .topbar-meta { gap: 6px; }
  .console-badge { padding: 6px 8px; font-size: 9px; }
  .kpi-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-bottom: 18px; }
  .kpi { padding: 13px 14px; }
  .kpi:nth-child(odd) { border-right: 1px solid var(--border-soft); }
  .kpi:nth-child(even) { border-right: 0; }
  .kpi:nth-child(n+3) { border-top: 1px solid var(--border-soft); }
  .kpi-value { font-size: 22px; }
  .page-head { align-items: flex-start; margin-bottom: 17px; }
  .page-title { font-size: 19px; }
  .page-stats { width: 100%; justify-content: space-between; gap: 12px; }
  .pstat { text-align: left; }
  .compliance-grid { grid-template-columns: 1fr; gap: 10px; }
  .section-card { padding: 16px; }
  .audit-row { align-items: flex-start; flex-wrap: wrap; gap: 5px 10px; }
  .audit-row time { width: auto; }
  .incident-body-inner { grid-template-columns: 1fr; gap: 14px; }
  .stDataFrame [data-testid="stDataFrameResizable"] { max-width: 100%; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior: auto !important; transition-duration: 0.01ms !important; animation-duration: 0.01ms !important; }
}

/* ── Signed-in SOC workspace polish ── */
header[data-testid="stHeader"] { background: transparent !important; }
/* Keep the header toolbar renderable: the sidebar reopen control lives inside it.
   Hide only the clutter (Deploy / main menu / status) so it stays out of the way. */
[data-testid="stToolbar"] { display: flex !important; background: transparent !important; }
[data-testid="stDeployButton"], [data-testid="stMainMenuButton"], [data-testid="stStatusWidget"] { display: none !important; }
[data-testid="stMainBlockContainer"] { padding-top: 0 !important; }
section[data-testid="stSidebar"] { background: linear-gradient(180deg, #0D1728 0%, #0A1220 100%) !important; }
section[data-testid="stSidebar"] > div { padding: 1rem .85rem 1.2rem !important; }
section[data-testid="stSidebar"] .stRadio > div > label { min-height: 40px; }
section[data-testid="stSidebar"] .stRadio > div > label:has(input:checked) {
  background: linear-gradient(90deg, rgba(44,119,224,.2), rgba(44,119,224,.06)) !important;
  border-left-color: #54A2FF !important;
  box-shadow: inset 0 0 0 1px rgba(84,162,255,.16) !important;
}
.topbar {
  margin: 0 -1rem 18px; padding: 14px 28px;
  background: rgba(9,16,29,.88); border-bottom-color: #1B2C43;
}
.topbar-crumb { color: #91A2BA; }
.console-badge { color: #69D4E8; border-color: rgba(77,190,219,.3); background: rgba(34,120,160,.1); }
.console-badge .pulse-dot { background: #47C7E1; box-shadow: 0 0 0 3px rgba(71,199,225,.12); }
.page-head { padding-top: 8px; }
.page-title { color: #F4F7FC; font-size: 27px; letter-spacing: -.04em; }
.page-sub { color: #9EADC1; }
.kpi-strip { grid-template-columns: repeat(5, minmax(0, 1fr)); background: rgba(14,24,40,.92); border-color: #22334A; }
.kpi { min-width: 0; }
.kpi-label { color: #A9B7CA; }
.kpi-value { color: #F3F7FD !important; font-variant-numeric: tabular-nums; }
.kpi.c-crit .kpi-value { color: #FF8291 !important; }
.kpi.c-high .kpi-value { color: #FFC66E !important; }
.kpi.c-low .kpi-value { color: #83B3FF !important; }
.section-card, .compliance-card, .sidebar-block, .audit-log {
  background: linear-gradient(145deg, rgba(17,29,47,.98), rgba(13,23,39,.98));
  border-color: #243750 !important;
}
.section-card h3 { color: #EAF1FA; }
.queue-heading { margin-top: 30px; }
.queue-heading h3 { color: #F1F5FB; font-size: 16px; }
.queue-heading span, .kpi-detail { color: #92A2B8; }
div[data-testid="stDataFrame"], [data-testid="stTable"] {
  border: 1px solid #243750; border-radius: 10px; overflow: hidden;
  background: #0D1727;
}
div[data-testid="stMetric"] { background: rgba(17,29,47,.9); border-color: #243750; }
div[data-testid="stMetricLabel"] { color: #9AAAC0; }
div[data-testid="stMetricValue"] { color: #F1F5FB; }
.stAlert { border-radius: 9px !important; }
.empty-state-note {
  display:flex; align-items:flex-start; gap:13px; margin: 0 0 22px; padding: 16px 18px;
  border:1px solid rgba(76,151,242,.28); border-radius:10px;
  background:linear-gradient(100deg,rgba(25,75,133,.2),rgba(13,24,40,.78));
}
.empty-state-icon {
  display:flex; align-items:center; justify-content:center; width:34px; height:34px; flex:none;
  border-radius:9px; color:#75B8FF; background:rgba(55,131,221,.14); border:1px solid rgba(89,160,245,.24);
}
.empty-state-title { color:#EAF3FF; font-weight:600; font-size:13px; margin-bottom:3px; }
.empty-state-copy { color:#9EADC1; font-size:12px; line-height:1.55; }
@media (max-width: 900px) {
  .topbar { margin: 0 -1rem 14px; padding: 13px 18px; }
  .kpi-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 600px) {
  .topbar { margin: 0 -1rem 12px; padding: 12px 14px; }
  .page-title { font-size: 21px; }
  .kpi-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

/* ── Reference console skin ── */
:root {
  --bg-base:#030A14; --bg-panel:#061226; --bg-raised:#0A1B35; --bg-input:#030D1B;
  --border:#174A83; --border-soft:#102E50; --text-1:#D6E7FA; --text-2:#8CAED3; --text-3:#5F83AA;
  --signal:#12D4E8; --signal-dim:#13547B; --crit:#FF466B; --high:#FFB82F; --med:#4CA8FF; --low:#11D9ED;
}
html, body, [class*="css"] { font-family:var(--mono) !important; color:var(--text-1); }
.stMarkdown, .stMarkdownContainer, .stCaption, .stTooltipIcon, [data-testid="stCaptionContainer"] { color:#8CAED3; font-family:var(--mono) !important; }
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, .stMarkdown h5 { color:#EAF3FF !important; font-family:var(--mono) !important; }
.stApp {
  background-color:#030A14 !important;
  background-image:linear-gradient(rgba(20,67,117,.10) 1px,transparent 1px),linear-gradient(90deg,rgba(20,67,117,.10) 1px,transparent 1px) !important;
  background-size:36px 36px !important;
}
[data-testid="stAppViewContainer"] { background:transparent !important; }
[data-testid="stMainBlockContainer"] { max-width:none !important; padding:0 24px 36px !important; }
header[data-testid="stHeader"] { height:0 !important; }
section[data-testid="stSidebar"] {
  width:236px !important; min-width:236px !important; max-width:236px !important;
  background:#040D1A !important; border-right:1px solid #12375E !important; box-shadow:none !important;
}
section[data-testid="stSidebar"] > div { width:236px !important; padding:18px 14px !important; }
/* Collapse / expand: let the sidebar truly reclaim its width when collapsed so the
   workspace reflows, and keep the reopen control visible and easy to hit. */
section[data-testid="stSidebar"][aria-expanded="false"],
section[data-testid="stSidebar"][aria-expanded="false"] > div {
  width:0 !important; min-width:0 !important; max-width:0 !important;
}
[data-testid="stExpandSidebarButton"] {
  width:34px !important; height:34px !important; min-width:34px !important; min-height:34px !important;
  background:#0A1B35 !important; border:1px solid #174A83 !important; border-radius:6px !important; color:#9CC4EE !important;
}
/* When collapsed, drop the command bar below the reopen button instead of under it. */
.stApp:not(:has(.terminal-signals)) .stAppViewContainer:has(section[data-testid="stSidebar"][aria-expanded="false"]) [data-testid="stMainBlockContainer"] {
  padding-top:44px !important;
}
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap:.48rem !important; }
section[data-testid="stSidebar"] .stButton > button {
  display:flex !important; min-height:44px !important; justify-content:flex-start !important; text-align:left !important;
  padding:9px 10px !important; border:1px solid transparent !important; border-left:2px solid transparent !important;
  border-radius:5px !important; background:transparent !important; color:#8CAED3 !important;
  font:12px var(--mono) !important; letter-spacing:.01em !important; box-shadow:none !important;
  transition:background .15s ease,border-color .15s ease,color .15s ease;
}
section[data-testid="stSidebar"] .st-key-soc_nav_1 button::before,
section[data-testid="stSidebar"] .st-key-soc_nav_2 button::before,
section[data-testid="stSidebar"] .st-key-soc_nav_3 button::before,
section[data-testid="stSidebar"] .st-key-soc_nav_4 button::before,
section[data-testid="stSidebar"] .st-key-soc_nav_5 button::before,
section[data-testid="stSidebar"] .st-key-soc_nav_6 button::before {
  display:inline-block; width:22px; flex:none; color:#4F83B7; font-size:9px; font-weight:500; letter-spacing:.02em;
}
section[data-testid="stSidebar"] .st-key-soc_nav_1 button::before { content:"01"; }
section[data-testid="stSidebar"] .st-key-soc_nav_2 button::before { content:"02"; }
section[data-testid="stSidebar"] .st-key-soc_nav_3 button::before { content:"03"; }
section[data-testid="stSidebar"] .st-key-soc_nav_4 button::before { content:"04"; }
section[data-testid="stSidebar"] .st-key-soc_nav_5 button::before { content:"05"; }
section[data-testid="stSidebar"] .st-key-soc_nav_6 button::before { content:"06"; }
section[data-testid="stSidebar"] .st-key-soc_nav_1 button[kind="primary"],
section[data-testid="stSidebar"] .st-key-soc_nav_2 button[kind="primary"],
section[data-testid="stSidebar"] .st-key-soc_nav_3 button[kind="primary"],
section[data-testid="stSidebar"] .st-key-soc_nav_4 button[kind="primary"],
section[data-testid="stSidebar"] .st-key-soc_nav_5 button[kind="primary"],
section[data-testid="stSidebar"] .st-key-soc_nav_6 button[kind="primary"] {
  background:linear-gradient(90deg,rgba(16,67,128,.42),rgba(10,35,70,.92)) !important;
  color:#F0F7FF !important; border:1px solid #174A83 !important;
  border-left:2px solid #27A2FF !important; box-shadow:inset 0 0 18px rgba(26,111,208,.08) !important;
}
section[data-testid="stSidebar"] .st-key-soc_nav_1 button[kind="primary"]::before,
section[data-testid="stSidebar"] .st-key-soc_nav_2 button[kind="primary"]::before,
section[data-testid="stSidebar"] .st-key-soc_nav_3 button[kind="primary"]::before,
section[data-testid="stSidebar"] .st-key-soc_nav_4 button[kind="primary"]::before,
section[data-testid="stSidebar"] .st-key-soc_nav_5 button[kind="primary"]::before,
section[data-testid="stSidebar"] .st-key-soc_nav_6 button[kind="primary"]::before { color:#67B3FF !important; }
section[data-testid="stSidebar"] .stButton > button:hover {
  background:#081A32 !important; color:#F0F7FF !important; border-color:#174A83 !important;
}
.st-key-command-bar {
  position:sticky; top:0; z-index:100; margin:0 -24px 22px !important; padding:15px 24px 13px !important;
  background:rgba(3,11,22,.97) !important; border-bottom:1px solid #102E50 !important;
  backdrop-filter:blur(14px);
}
.st-key-command-bar [data-testid="stVerticalBlock"] { gap:0 !important; }
.st-key-command-bar [data-testid="stHorizontalBlock"] { align-items:center !important; }
.soc-crumb { color:#BED3EA; font-size:12px; white-space:nowrap; }
.soc-crumb:first-letter { color:#69A8E8; }
.soc-crumb span { color:#4F78A3; padding:0 6px; }
.sensor-status { display:flex; align-items:center; justify-content:flex-end; gap:8px; white-space:nowrap; color:#12D4E8; font-size:10px; }
.sensor-status i { width:7px; height:7px; border-radius:50%; background:#12D4E8; box-shadow:0 0 9px rgba(18,212,232,.65); }
.st-key-command-bar .stSelectbox [data-baseweb="select"], .st-key-command-bar .stTextInput input {
  min-height:36px !important; height:36px !important; border-radius:6px !important;
  background:#030B16 !important; border:1px solid #16518D !important; color:#D6E7FA !important;
  font:12px var(--mono) !important;
}
.st-key-command-bar .stTextInput input { padding:0 12px !important; }
.st-key-command-bar [data-baseweb="select"] * { color:#D6E7FA !important; }

/* Settings: a single right-aligned gear icon button (pinned to a 36px box so the
   icon and the dropdown chevron can never collide in a narrow column). */
.st-key-command-bar [data-testid="stColumn"]:last-child {
  flex:0 0 36px !important; width:36px !important; min-width:36px !important;
}
.st-key-command-bar [data-testid="stPopover"] { width:100% !important; }
.st-key-command-bar [data-testid="stPopoverButton"] {
  width:36px !important; min-width:36px !important; height:36px !important; min-height:36px !important;
  padding:0 !important; justify-content:center !important;
  border:1px solid #16518D !important; border-radius:6px !important;
  background:#030B16 !important; color:#9FC4EA !important;
}
.st-key-command-bar [data-testid="stPopoverButton"]:hover {
  border-color:#258CFF !important; background:#061226 !important; color:#E6F1FF !important;
}
/* the inner flex container carries a -5px right margin for the chevron slot;
   reset it so the lone gear sits dead centre in the square */
.st-key-command-bar [data-testid="stPopoverButton"] > div { margin:0 !important; gap:0 !important; }
/* hide the popover's auto chevron so the control stays a clean square icon */
.st-key-command-bar [data-testid="stPopoverButton"] > div > div[aria-hidden="true"] { display:none !important; }
.page-head { margin:0 0 16px !important; padding-top:0 !important; }
.page-title { font:700 23px/1.25 var(--mono) !important; letter-spacing:0 !important; color:#F1F7FF !important; }
.page-sub { font:12px/1.55 var(--mono) !important; color:#779CC4 !important; max-width:820px; }
.kpi-strip { gap:12px; border:0 !important; border-radius:0 !important; overflow:visible !important; background:transparent !important; box-shadow:none !important; margin:0 0 14px !important; }
.kpi { min-height:92px; box-sizing:border-box; padding:13px 14px !important; border:1px solid #164B83; border-top:2px solid #1A91E9; border-radius:7px; background:#061226 !important; box-shadow:none !important; }
.kpi:nth-child(1) { border-top-color:#11D9ED; }.kpi:nth-child(3) { border-top-color:#FF466B; }.kpi:nth-child(4) { border-top-color:#FFB82F; }
.kpi-label { color:#6D91B7 !important; font:10px var(--mono) !important; letter-spacing:.08em !important; }
.kpi-value { font:600 27px/1.1 var(--mono) !important; color:#F4F8FD !important; letter-spacing:0 !important; }
.kpi.c-signal .kpi-value { color:#11D9ED !important; }.kpi.c-crit .kpi-value { color:#FF466B !important; }.kpi.c-high .kpi-value { color:#FFB82F !important; }
.kpi-detail { color:#6D91B7 !important; font:10px var(--mono) !important; }
.asset-kpis { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:0 0 14px; }
.asset-kpi { min-width:0; padding:13px 14px; border:1px solid #164B83; border-top:2px solid #258CFF; border-radius:7px; background:#061226; }
.asset-kpi > div { color:#6D91B7; font-size:9px; letter-spacing:.1em; }
.asset-kpi strong { display:block; margin:5px 0 2px; color:#F4F8FD; font-size:25px; font-weight:600; }
.asset-kpi small { color:#6D91B7; font-size:10px; }
.asset-kpi.accent-cyan { border-top-color:#11D9ED; }.asset-kpi.accent-cyan strong { color:#11D9ED; }
.asset-kpi.accent-amber { border-top-color:#FFB82F; }.asset-kpi.accent-amber strong { color:#FFB82F; }
.asset-kpi.accent-blue { border-top-color:#4CA8FF; }
.section-card, .compliance-card, .sidebar-block, .audit-log, details[data-testid="stExpander"], .stForm {
  background:#061226 !important; border:1px solid #174A83 !important; border-radius:8px !important; box-shadow:none !important;
}
.section-card { padding:16px !important; }
.section-card h3 { color:#769CC4 !important; font:10px var(--mono) !important; letter-spacing:.12em !important; text-transform:uppercase; margin-bottom:15px !important; }
.queue-heading { margin:22px 0 10px !important; }
.queue-heading h3 { color:#D6E7FA !important; font:12px var(--mono) !important; text-transform:uppercase; letter-spacing:.1em; }
.queue-heading span { color:#6387AE !important; font:10px var(--mono) !important; }
div[data-testid="stDataFrame"], [data-testid="stTable"] { background:#061226 !important; border:1px solid #174A83 !important; border-radius:8px !important; box-shadow:none !important; }
div[data-testid="stMetric"] { background:#061226 !important; border:1px solid #174A83 !important; border-radius:7px !important; box-shadow:none !important; }
div[data-testid="stMetricLabel"] { color:#7197BF !important; font:10px var(--mono) !important; text-transform:uppercase; }
div[data-testid="stMetricValue"] { color:#F3F8FF !important; font-family:var(--mono) !important; }
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
  border:1px solid #1761A9 !important; border-radius:6px !important; background:#061226 !important;
  color:#A6C5E5 !important; font:11px var(--mono) !important; box-shadow:none !important;
}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
  background:#145AC8 !important; border-color:#2A99FF !important; color:#F7FBFF !important; font-weight:700 !important;
}
.stButton > button:hover, .stDownloadButton > button:hover { border-color:#3CA5FF !important; color:#F7FBFF !important; transform:none !important; }
.stTextInput input, .stSelectbox [data-baseweb="select"], .stMultiSelect [data-baseweb="select"] {
  background:#030D1B !important; border:1px solid #174A83 !important; color:#D6E7FA !important; border-radius:6px !important; font:12px var(--mono) !important;
}
.stTextInput label, .stSelectbox label, .stMultiSelect label { color:#7197BF !important; font:10px var(--mono) !important; }
[data-baseweb="popover"], [role="listbox"], [data-baseweb="menu"] { background:#061226 !important; border:1px solid #174A83 !important; }
[role="option"], [data-baseweb="menu"] * { color:#C3D8EF !important; font-family:var(--mono) !important; }
[role="option"]:hover, [aria-selected="true"][role="option"] { background:#0A2346 !important; }
div[data-testid="stAlert"] { background:#061226 !important; border:1px solid #174A83 !important; color:#BBD0E8 !important; }
div[data-testid="stAlert"] p { color:#BBD0E8 !important; font-family:var(--mono) !important; }
div[data-testid="stNotification"] { background:#061226 !important; border:1px solid #174A83 !important; }
[data-testid="stTabs"] button { color:#8CAED3 !important; font-family:var(--mono) !important; }
[data-testid="stTabs"] button[aria-selected="true"] { color:#12D4E8 !important; border-bottom-color:#12D4E8 !important; }
[data-testid="stJson"] { background:#030D1B !important; border:1px solid #174A83 !important; border-radius:7px; }
section[data-testid="stSidebar"] .sidebar-block { padding:12px !important; }
section[data-testid="stSidebar"] .live-tag { color:#11D9ED !important; font-size:9px !important; }
section[data-testid="stSidebar"] .live-port { color:#F2F7FF !important; font-size:19px !important; }
section[data-testid="stSidebar"] .stButton > button { min-height:38px; }
.slice-table th, .slice-table td { border-color:#12375E !important; }
.slice-table th { background:#081A32 !important; color:#6F94BC !important; font:9px var(--mono) !important; }
.slice-table td { color:#B5CCE5 !important; font:11px var(--mono) !important; }
.incident, .audit-log { background:#061226 !important; border-color:#174A83 !important; }
details[data-testid="stExpander"] summary { color:#D6E7FA !important; font-family:var(--mono) !important; }
hr { border-color:#12375E !important; }
.empty-state-note { background:rgba(7,24,47,.9) !important; border-color:#174A83 !important; border-radius:8px !important; }
.empty-state-title { color:#DAEAFB !important; font-family:var(--mono) !important; }
.empty-state-copy { color:#8CAED3 !important; font-family:var(--mono) !important; }
.event-detail-card { min-height:360px; padding:15px; border:1px solid #174A83; border-radius:8px; background:#061226; }
.event-detail-heading { margin:0 0 14px; color:#6F94BC; font-size:10px; letter-spacing:.12em; }
.event-detail-row { display:grid; grid-template-columns:72px minmax(0,1fr); gap:8px; padding:5px 0; color:#8CAED3; font-size:11px; }
.event-detail-row b { min-width:0; color:#BBD0E8; font-weight:400; overflow-wrap:anywhere; }
.event-verdict { margin-top:14px; padding-top:10px; border-top:1px solid #12375E; font-size:10px; letter-spacing:.08em; font-weight:700; }
.report-card, .report-scope-card { min-height:110px; margin-bottom:9px; padding:15px; border:1px solid #174A83; border-radius:8px; background:#061226; }
.report-card-title { color:#EDF5FF; font-size:12px; font-weight:600; margin-bottom:8px; }
.report-card-copy { color:#7FA2C7; font-size:11px; line-height:1.55; }
.report-scope-card { min-height:0; margin-top:22px; }
[data-testid="stMain"] .stRadio > div { gap:7px !important; }
[data-testid="stMain"] .stRadio > div > label {
  min-height:62px; padding:10px 11px !important; align-items:flex-start !important; white-space:pre-line;
  border:1px solid #174A83 !important; border-radius:7px !important; background:#061226 !important;
  color:#AFC6E0 !important; font:11px/1.55 var(--mono) !important;
}
[data-testid="stMain"] .stRadio > div > label > span:first-child { display:none !important; }
[data-testid="stMain"] .stRadio > div > label:has(input:checked) {
  background:#0A2346 !important; border-color:#268DE5 !important; color:#F0F7FF !important;
}
@media(max-width:1000px) {
  section[data-testid="stSidebar"], section[data-testid="stSidebar"] > div { width:205px !important; min-width:205px !important; max-width:205px !important; }
  [data-testid="stMainBlockContainer"] { padding-left:16px !important; padding-right:16px !important; }
  .st-key-command-bar { margin-left:-16px !important; margin-right:-16px !important; padding-left:16px !important; padding-right:16px !important; }
}
@media(max-width:760px) {
  .kpi-strip { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .asset-kpis { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .st-key-command-bar [data-testid="stHorizontalBlock"] { flex-wrap:wrap; }
  .soc-crumb { padding:4px 0; }
}
/* ── User management (admin) ───────────────────────────────────────── */
section[data-testid="stSidebar"] .st-key-nav_users button::before {
  display:inline-block; width:22px; flex:none; color:#4F83B7; font-size:9px; font-weight:500; content:"07";
}
section[data-testid="stSidebar"] .st-key-nav_users button[kind="primary"] {
  background:linear-gradient(90deg,rgba(16,67,128,.42),rgba(10,35,70,.92)) !important;
  color:#F0F7FF !important; border:1px solid #174A83 !important;
  border-left:2px solid #27A2FF !important; box-shadow:inset 0 0 18px rgba(26,111,208,.08) !important;
}
section[data-testid="stSidebar"] .st-key-nav_users button[kind="primary"]::before { color:#67B3FF !important; }
/* ── Incident queue ─────────────────────────────────────────────────── */
.inc-kpis { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:0 0 16px; }
.inc-kpi { padding:12px 15px; border:1px solid #14407A; border-top:2px solid #3B9EFF; border-radius:8px; background:rgba(6,18,40,.92); box-shadow:0 0 26px rgba(34,120,255,.10); }
.inc-kpi s { display:block; text-decoration:none; font:10px var(--mono); letter-spacing:1.2px; color:#6F93BF; }
.inc-kpi b { display:block; margin-top:3px; font:600 26px/1.15 var(--mono); color:#F4F8FD; }
.inc-kpi.open b { color:#3B9EFF; }
.inc-kpi.crit { border-top-color:#FF5C7A; } .inc-kpi.crit b { color:#FF5C7A; }
.inc-kpi.med b { color:#3B9EFF; }
.inc-kpi.new { border-top-color:#22D3EE; } .inc-kpi.new b { color:#22D3EE; }

.st-key-inc_queue_panel { border:1px solid #14407A; border-radius:10px; background:rgba(6,18,40,.92); padding:14px 16px; max-height:680px; overflow-y:auto; box-shadow:0 0 26px rgba(34,120,255,.10); }
.st-key-inc_detail_panel { border:1px solid #14407A; border-radius:10px; background:rgba(6,18,40,.92); padding:16px 18px; box-shadow:0 0 26px rgba(34,120,255,.10); }
.st-key-inc_queue_panel [data-testid="stVerticalBlock"] { gap:2px !important; }
.st-key-inc_queue_panel [data-testid="stHorizontalBlock"] { gap:6px !important; }
.st-key-inc_detail_panel [data-testid="stVerticalBlock"] { gap:6px !important; }
.st-key-inc_queue_panel .stButton > button {
  border:0 !important; background:transparent !important; min-height:0 !important; height:auto !important;
  padding:2px 0 !important; justify-content:flex-start !important; text-align:left !important;
  color:#BFD8F3 !important; font:600 11px var(--mono) !important; box-shadow:none !important;
}
.st-key-inc_queue_panel .stButton > button:hover { color:#FFFFFF !important; text-decoration:underline !important; border:0 !important; background:transparent !important; }
.inc-panel-head { display:flex; justify-content:space-between; align-items:center; font:10px var(--mono); letter-spacing:1.5px; color:#6F93BF; margin-bottom:10px; }
.inc-filters { margin-bottom:10px; }
.inc-th { font:10px var(--mono); letter-spacing:1.2px; color:#6F93BF; border-bottom:1px solid #14407A; padding:6px 2px; }
.inc-det { color:#C9DDF7; font:11.5px/1.4 var(--mono); white-space:normal; }
.sv { display:inline-block; font:700 10px var(--mono); padding:2px 8px; border-radius:99px; border:1px solid; letter-spacing:.6px; }
.sv.c { color:#FF5C7A; border-color:#FF5C7A; } .sv.h { color:#F5B942; border-color:#F5B942; }
.sv.m { color:#3B9EFF; border-color:#3B9EFF; } .sv.l { color:#22D3EE; border-color:#22D3EE; }
.chip { display:inline-block; border:1px solid #1D4F8F; border-radius:99px; padding:3px 10px; margin-right:6px; color:#9FC4F0; font:11px var(--mono); }
.chip.on { background:#0B2248; color:#FFFFFF; border-color:#3B9EFF; }
.inc-detail-head { display:flex; justify-content:space-between; align-items:center; font:10px var(--mono); letter-spacing:1.5px; color:#6F93BF; margin-bottom:12px; }
.inc-detail-title { color:#FFFFFF; font:700 16px/1.35 var(--mono); margin-bottom:12px; }
.inc-pre { margin:0 0 4px; font:11.5px/1.9 var(--mono); color:#8FB0DA; white-space:pre-wrap; }
.inc-pre b { color:#D6E8FF; font-weight:400; }
.inc-desc { color:#C9DDF7; font:11.5px/1.65 var(--mono); margin:0 0 10px; white-space:pre-wrap; }
.inc-log { border:1px solid #0F2B52; border-radius:6px; background:#030B16; padding:10px 12px; max-height:240px; overflow:auto; }
.inc-log-head { font:10px var(--mono); letter-spacing:.6px; color:#22D3EE; border-bottom:1px solid #0F2B52; padding-bottom:6px; margin-bottom:6px; }
.inc-log-line { display:flex; gap:10px; font:11px/1.9 var(--mono); }
.inc-log-line span { color:#6F93BF; min-width:132px; flex:none; }
.inc-log-line b { color:#D6E8FF; font-weight:400; word-break:break-word; }
.inc-subhead { font:10px var(--mono); letter-spacing:1.5px; color:#6F93BF; margin:16px 0 8px; }
.st-key-inc_triage [data-testid="stHorizontalBlock"] { gap:8px !important; }
.st-key-inc_triage .stButton > button { min-height:30px !important; padding:3px 10px !important; border-radius:99px !important; font:11px var(--mono) !important; }
.st-key-inc_triage .stButton > button[kind="primary"] { background:#0B2248 !important; color:#FFFFFF !important; border-color:#3B9EFF !important; }
@media(max-width:760px) { .inc-kpis { grid-template-columns:repeat(2,minmax(0,1fr)); } }
</style>
"""
