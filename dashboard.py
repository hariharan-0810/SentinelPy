import json
import pandas as pd
import streamlit as st
from sentinelpy.database import connect, init_db, set_alert_status
from sentinelpy.config import DB_PATH
from sentinelpy.reports import export

st.set_page_config(page_title="SentinelPy SOC", page_icon="🛡️", layout="wide")
st.title("SentinelPy | Live SOC Dashboard")
st.caption("Detection, alerting and reporting only. No automatic blocking or remediation.")
init_db()

live = st.sidebar.toggle("Live refresh", value=True)
every = st.sidebar.slider("Refresh every (seconds)", 2, 60, 5, disabled=not live)
st.sidebar.write("Database: " + str(DB_PATH))
st.sidebar.info("Run `python -m sentinelpy.cli monitor` in another terminal to feed this dashboard live.")
st.sidebar.warning("A detection is a lead for investigation, not proof of compromise.")

SEV_ORDER = ["Critical", "High", "Medium", "Low"]


def body():
    db = connect()
    try:
        alerts = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC", db)
        events = pd.read_sql_query("SELECT * FROM events ORDER BY id DESC LIMIT 1000", db)
    finally:
        db.close()

    cols = st.columns(5)
    cols[0].metric("Recent events", len(events))
    cols[1].metric("Alerts", len(alerts))
    sev = alerts.severity if not alerts.empty else pd.Series(dtype=str)
    cols[2].metric("Critical", int((sev == "Critical").sum()))
    cols[3].metric("High", int((sev == "High").sum()))
    cols[4].metric("New (unreviewed)", int((alerts.status == "New").sum()) if not alerts.empty else 0)

    if not alerts.empty and (alerts.severity == "Critical").any() and (alerts[alerts.severity == "Critical"].status == "New").any():
        st.error("Unreviewed CRITICAL alerts - investigate first.")

    st.subheader("Alerts")
    if alerts.empty:
        st.info("No alerts yet. Start the live monitor, or run the collector on sample logs.")
    else:
        f1, f2, f3 = st.columns(3)
        chosen = f1.selectbox("Severity", ["All"] + [s for s in SEV_ORDER if s in set(alerts.severity)], key="sev")
        stat = f2.selectbox("Status", ["All", "New", "Acknowledged", "Resolved", "False positive"], key="stat")
        query = f3.text_input("Search alerts", key="q")
        shown = alerts
        if chosen != "All": shown = shown[shown.severity == chosen]
        if stat != "All": shown = shown[shown.status == stat]
        if query:
            mask = shown.astype(str).apply(lambda col: col.str.contains(query, case=False, na=False)).any(axis=1)
            shown = shown[mask]
        shown = shown.assign(_rank=shown.severity.map({s: i for i, s in enumerate(SEV_ORDER)}).fillna(9)) \
                     .sort_values(["_rank", "id"], ascending=[True, False])
        st.dataframe(shown[["id", "created_at", "severity", "rule_id", "title", "src_ip", "event_count", "status", "notified", "description"]],
                     use_container_width=True, hide_index=True)
        if not shown.empty:
            aid = st.selectbox("Inspect alert ID", shown.id.tolist(), key="aid")
            item = shown[shown.id == aid].iloc[0]
            st.write({k: item[k] for k in ("created_at", "severity", "rule_id", "title", "src_ip", "event_count", "description", "status")})
            try: st.code(json.dumps(json.loads(item.evidence), indent=2), language="json")
            except Exception: st.text(str(item.evidence))
            c1, c2 = st.columns([2, 1])
            new_status = c1.selectbox("Set status", ["New", "Acknowledged", "Resolved", "False positive"],
                                      index=["New", "Acknowledged", "Resolved", "False positive"].index(item.status)
                                      if item.status in ["New", "Acknowledged", "Resolved", "False positive"] else 0, key="newstat")
            if c2.button("Update status", key="upd"):
                d = connect()
                try: set_alert_status(d, int(aid), new_status)
                finally: d.close()
                st.success(f"Alert {aid} set to {new_status}")

    st.subheader("Recent events")
    if events.empty:
        st.info("No events stored.")
    else:
        e1, e2 = st.columns(2)
        source = e1.selectbox("Event source", ["All"] + sorted(events.source.dropna().unique().tolist()), key="src")
        hosts = sorted(events.host.dropna().unique().tolist()) if "host" in events else []
        host = e2.selectbox("Host", ["All"] + hosts, key="host")
        ev = events
        if source != "All": ev = ev[ev.source == source]
        if host != "All": ev = ev[ev.host == host]
        st.dataframe(ev[["event_time", "host", "source", "src_ip", "event_type", "username", "status_code", "request_path", "message"]],
                     use_container_width=True, hide_index=True)

    st.subheader("Export incident report")
    for fmt in ("csv", "json", "html"):
        if st.button("Generate " + fmt.upper() + " report", key="make_" + fmt):
            path, count = export(fmt)
            st.success(f"Created {count} alerts at {path}")
            st.download_button("Download " + fmt.upper(), path.read_bytes(), file_name=path.name,
                               mime={"csv": "text/csv", "json": "application/json", "html": "text/html"}[fmt], key="download_" + fmt)


# Re-run just this section on a timer so alerts appear without a manual page reload.
(st.fragment(run_every=every)(body) if live else body)()
