import pandas as pd
import matplotlib.pyplot as plt

INPUT_CSV = "network_logs.csv"
REPORT_CSV = "suspicious_activity_report.csv"
PLOT_PNG = "active_ips_chart.png"
df = pd.read_csv(INPUT_CSV)
df.columns = df.columns.str.strip().str.lower()
if 'action' in df.columns:
    df['action'] = df['action'].astype(str).str.strip().str.lower()
if 'status' in df.columns:
    df['status'] = df['status'].astype(str).str.strip().str.lower()
if 'source_ip' in df.columns:
    df['source_ip'] = df['source_ip'].astype(str).str.strip()
if {'action', 'source_ip'}.issubset(df.columns):
    fl = df[df['action'] == 'failed_login'].copy()
    failed_by_ip = (
        fl.groupby('source_ip', dropna=False)
          .size()
          .reset_index(name='failed_login_events')
    )
    failed_status = (
        fl.groupby(['source_ip', 'status'], dropna=False)
          .size()
          .unstack(fill_value=0)
          .reset_index()
    )
else:
    failed_by_ip = pd.DataFrame(columns=['source_ip', 'failed_login_events'])
    failed_status = pd.DataFrame()

if {'action', 'source_ip', 'destination_ip'}.issubset(df.columns):
    ps = df[df['action'] == 'port_scan'].copy()
    port_scan_events = (
        ps.groupby('source_ip', dropna=False)
          .size()
          .reset_index(name='port_scan_events')
    )
    port_scan_unique_targets = (
        ps.groupby('source_ip', dropna=False)['destination_ip']
          .nunique()
          .reset_index(name='port_scan_unique_targets')
    )
else:
    port_scan_events = pd.DataFrame(columns=['source_ip', 'port_scan_events'])
    port_scan_unique_targets = pd.DataFrame(columns=['source_ip', 'port_scan_unique_targets'])

if 'source_ip' in df.columns and 'action' in df.columns:
    action_pivot = (
        pd.crosstab(df['source_ip'], df['action'])
          .reset_index()
          .rename_axis(None, axis=1)
    )
    activity_counts = (
        df.groupby('source_ip', dropna=False)
          .size()
          .reset_index(name='total_activity_count')
    )
else:
    action_pivot = pd.DataFrame()
    activity_counts = pd.DataFrame(columns=['source_ip', 'total_activity_count'])

parts = [activity_counts, failed_by_ip, port_scan_events, port_scan_unique_targets]
report = activity_counts.copy()
for part in [failed_by_ip, port_scan_events, port_scan_unique_targets]:
    if not part.empty:
        report = report.merge(part, on='source_ip', how='outer')
if not action_pivot.empty:
    report = report.merge(action_pivot, on='source_ip', how='outer')

report = report.fillna(0)
num_cols = [c for c in report.columns if c != 'source_ip']
report[num_cols] = report[num_cols].apply(pd.to_numeric, errors='coerce').fillna(0).astype(int)

sort_cols = []
if 'failed_login_events' in report.columns:
    sort_cols.append('failed_login_events')
if 'port_scan_events' in report.columns:
    sort_cols.append('port_scan_events')
sort_cols.append('total_activity_count')
report = report.sort_values(by=sort_cols, ascending=False)

report.to_csv(REPORT_CSV, index=False)
print(f"Saved {REPORT_CSV} rows: {len(report)}")

if not activity_counts.empty:
    top10 = activity_counts.sort_values('total_activity_count', ascending=False).head(10).copy()
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(top10['source_ip'], top10['total_activity_count'], color='C0')
    ax.set_title("Top 10 Most Active Source IPs")
    ax.set_xlabel("Source IP")
    ax.set_ylabel("Total Activity Count")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(PLOT_PNG)
    print(f"Saved {PLOT_PNG}")
else:
    print("No activity_counts to plot.")
