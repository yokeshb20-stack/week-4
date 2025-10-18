# WEEK-4
Overview

A brief guide to run the network log analysis script, understand its outputs, and interpret suspicious findings. The script detects repeated failed logins, port-scan activity, and the most active source IPs from network_logs.csv.

Requirements

Python 3.8 or newer

pandas

matplotlib Install dependencies with:

pip install pandas matplotlib

Files in the repository

network_logs.csv — raw network log input

Program.py — main Python script that produces the report and chart

suspicious_activity_report OutPut.csv — generated CSV summarizing suspicious activity after running the script

active_ips_chart OutPut.png — saved bar chart of the top active source IPs

README.md — this file

Steps to run
Place network_logs.csv in the same folder as analysis_script.py.

From the terminal run:

python Program.py

On success the script saves suspicious_activity_report.csv and active_ips_chart.png in the same folder and prints a short summary to the console.

What the script does step by step
Loads and normalizes the CSV column names.

Normalizes the action and status text to lowercase and trims whitespace.

Counts failed login events by source IP using explicit matching for action == failed_login.

Counts port-scan events by source IP and computes the number of unique destination targets per source IP to help identify scanning behavior.

Computes a total activity count per source IP and a per-action breakdown (pivot) so you can see which actions contributed to activity.

Merges summaries into suspicious_activity_report.csv, fills missing values with zeros, and sorts by suspicious metrics such as failed_login_events and port_scan_events.

Produces a top-10 bar chart of most active source IPs saved to active_ips_chart.png.

How to read suspicious_activity_report.csv
source_ip — IP address of the source.

total_activity_count — total number of log entries for that source IP.

failed_login_events — number of events where action == failed_login. High numbers indicate possible brute-force attempts.

port_scan_events — total port_scan events from that source IP.

port_scan_unique_targets — unique destination IPs targeted by port_scan actions. High unique targets indicate scanning or enumeration.

other action columns — counts for other action types present in the logs such as login, logout, file_access, password_change
