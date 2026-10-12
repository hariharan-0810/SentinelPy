from pathlib import Path
import csv, html, json
from .config import REPORTS_DIR
from .database import connect

def all_alerts():
    db=connect()
    try: return [dict(r) for r in db.execute("SELECT * FROM alerts ORDER BY created_at DESC,id DESC")]
    finally: db.close()

def export(fmt="json", output=None):
    if fmt not in ("csv","json","html"): raise ValueError("format must be csv, json, or html")
    path=Path(output) if output else REPORTS_DIR/f"alerts.{fmt}"
    path.parent.mkdir(parents=True,exist_ok=True)
    data=all_alerts()
    if fmt=="json":
        path.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
    elif fmt=="csv":
        fields=["id","created_at","rule_id","severity","title","src_ip","event_count","description","status","evidence"]
        with path.open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore"); w.writeheader(); w.writerows(data)
    else:
        cols=("created_at","severity","rule_id","title","src_ip","event_count","description","status")
        head="".join("<th>"+html.escape(c)+"</th>" for c in cols)
        body="".join("<tr>"+"".join("<td>"+html.escape(str(row.get(c,"")))+"</td>" for c in cols)+"</tr>" for row in data)
        page=("<!doctype html><html><head><meta charset='utf-8'><title>SentinelPy report</title>"
              "<style>body{font-family:system-ui;margin:2rem}table{border-collapse:collapse;width:100%}"
              "th,td{border:1px solid #ddd;padding:.5rem;text-align:left}td{overflow-wrap:anywhere}</style></head>"
              "<body><h1>SentinelPy Alert Report</h1><p>Alerts require analyst review.</p><table><thead><tr>"
              +head+"</tr></thead><tbody>"+body+"</tbody></table></body></html>")
        path.write_text(page,encoding="utf-8")
    return path,len(data)
