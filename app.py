import os
import sys
import json
import subprocess
import pandas as pd
import numpy as np
import networkx as nx
from flask import Flask, jsonify, render_template, request

# Import functions from graph_engine
from graph_engine import (
    build_identity_graph,
    calculate_effective_privileges,
    detect_anomalies,
    detect_cross_platform_sprawl
)

app = Flask(__name__)

# Constants for paths
IDENTITIES_CSV = "identities.csv"
PERMISSIONS_CSV = "permissions.csv"
MAPPINGS_CSV = "group_mappings.csv"
AUDIT_EVENTS_CSV = "audit_events.csv"
RISK_REPORT_JSON = "risk_report.json"
CLUSTERED_INCIDENTS_JSON = "clustered_incidents.json"

def run_pipeline():
    """Runs the risk scoring and incident clustering scripts to update files on disk."""
    try:
        # Run risk_scorer.py
        subprocess.run([sys.executable, "risk_scorer.py"], check=True)
        # Run incident_generator.py
        subprocess.run([sys.executable, "incident_generator.py"], check=True)
        return True
    except Exception as e:
        print(f"Pipeline error: {e}")
        return False

def load_data():
    """Helper to load all datasets and return raw dataframes/JSONs."""
    try:
        df_id = pd.read_csv(IDENTITIES_CSV).fillna('')
        df_perm = pd.read_csv(PERMISSIONS_CSV).fillna('')
        df_map = pd.read_csv(MAPPINGS_CSV).fillna('')
        
        # Handle datetime parsing for events
        df_ev = pd.read_csv(AUDIT_EVENTS_CSV)
        df_ev['timestamp'] = pd.to_datetime(df_ev['timestamp'], utc=True)
        
        # Load JSON files
        with open(RISK_REPORT_JSON, 'r') as f:
            risk_report = json.load(f)
            
        with open(CLUSTERED_INCIDENTS_JSON, 'r') as f:
            clustered_incidents = json.load(f)
            
        return df_id, df_perm, df_map, df_ev, risk_report, clustered_incidents
    except Exception as e:
        print(f"Data loading error: {e}")
        return None, None, None, None, [], []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/summary')
def get_summary():
    df_id, _, _, _, risk_report, clustered_incidents = load_data()
    if df_id is None:
        return jsonify({"error": "Failed to load database"}), 500
        
    total_identities = len(df_id)
    
    # Calculate average hybrid risk score
    scores = [u.get('hybrid_risk_score', 0) for u in risk_report]
    avg_risk = round(sum(scores) / len(scores), 2) if scores else 0.0
    
    # Critical and High risk counts
    critical_count = sum(1 for s in scores if s >= 85)
    high_count = sum(1 for s in scores if 70 <= s < 85)
    
    # Active accounts breakdown
    ad_active = len(df_id[df_id['ad_status'] == 'Active'])
    aws_active = len(df_id[df_id['aws_status'] == 'Active'])
    okta_active = len(df_id[df_id['okta_status'] == 'Active'])
    
    # Count incident types
    total_incidents = len(clustered_incidents)
    critical_incidents = sum(1 for inc in clustered_incidents if inc.get('severity') == 'CRITICAL')
    
    return jsonify({
        "total_identities": total_identities,
        "avg_risk_score": avg_risk,
        "critical_users": critical_count,
        "high_users": high_count,
        "total_incidents": total_incidents,
        "critical_incidents": critical_incidents,
        "platform_active_accounts": {
            "AD": ad_active,
            "AWS": aws_active,
            "Okta": okta_active
        }
    })

@app.route('/api/identities')
def get_identities():
    df_id, _, _, _, risk_report, _ = load_data()
    if df_id is None:
        return jsonify([])
        
    # Build dictionary of risk data indexed by emp_id
    risk_dict = {u['emp_id']: u for u in risk_report}
    
    identities_list = []
    for _, row in df_id.iterrows():
        emp_id = row['emp_id']
        risk_data = risk_dict.get(emp_id, {})
        
        identities_list.append({
            "emp_id": emp_id,
            "hr_status": row['hr_status'],
            "department": row['department'],
            "title": row['title'],
            "justification": row['justification'],
            "ad_id": row['ad_id'],
            "ad_status": row['ad_status'],
            "aws_id": row['aws_id'],
            "aws_status": row['aws_status'],
            "okta_id": row['okta_id'],
            "okta_status": row['okta_status'],
            "last_login": row['last_login'],
            "termination_date": row['termination_date'],
            "hybrid_risk_score": risk_data.get('hybrid_risk_score', 0.0),
            "ml_risk_score": risk_data.get('ml_risk_score', 0.0),
            "framework_violations": risk_data.get('framework_violations', [])
        })
        
    # Sort by hybrid risk score descending
    identities_list.sort(key=lambda x: x['hybrid_risk_score'], reverse=True)
    return jsonify(identities_list)

@app.route('/api/identity/<emp_id>')
def get_identity_details(emp_id):
    df_id, _, _, df_ev, risk_report, _ = load_data()
    if df_id is None:
        return jsonify({"error": "Failed to load database"}), 500
        
    # Find employee metadata
    user_row = df_id[df_id['emp_id'] == emp_id]
    if user_row.empty:
        return jsonify({"error": "Employee not found"}), 404
        
    user_meta = user_row.iloc[0].to_dict()
    
    # Find risk scores and features
    risk_data = next((u for u in risk_report if u['emp_id'] == emp_id), {})
    
    # Extract audit events for this employee's account IDs
    account_ids = []
    if user_meta.get('ad_id'): account_ids.append(user_meta['ad_id'])
    if user_meta.get('aws_id'): account_ids.append(user_meta['aws_id'])
    if user_meta.get('okta_id'): account_ids.append(user_meta['okta_id'])
    
    user_events = []
    if account_ids and df_ev is not None:
        df_user_ev = df_ev[df_ev['platform_id'].isin(account_ids)].copy()
        # Sort by timestamp descending
        df_user_ev = df_user_ev.sort_values(by='timestamp', ascending=False)
        for _, row in df_user_ev.iterrows():
            user_events.append({
                "event_id": row['event_id'],
                "timestamp": row['timestamp'].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "platform_id": row['platform_id'],
                "platform": row['platform'],
                "action": row['action'],
                "status": row['status']
            })
            
    # Build identity graph subgraph
    G = build_identity_graph(IDENTITIES_CSV, PERMISSIONS_CSV, MAPPINGS_CSV)
    graph_data = {"nodes": [], "edges": []}
    
    if G.has_node(emp_id):
        descendants = nx.descendants(G, emp_id)
        nodes_in_subgraph = {emp_id} | descendants
        subgraph = G.subgraph(nodes_in_subgraph)
        
        for node, data in subgraph.nodes(data=True):
            node_type = data.get('type', 'unknown')
            label = str(node)
            status = data.get('status', data.get('hr_status', ''))
            
            if node_type == 'identity':
                label = f"Identity: {node}"
            elif node_type == 'account':
                label = f"{data.get('platform')} Account\n{node}"
            elif node_type == 'group':
                label = f"Group/Role\n{node}"
            elif node_type == 'permission':
                parts = str(node).split('_', 1)
                level = parts[1] if len(parts) > 1 else parts[0]
                label = f"Entitlement\n{level}"
                
            graph_data['nodes'].append({
                "id": node,
                "label": label,
                "type": node_type,
                "platform": data.get('platform', ''),
                "status": status,
                "hr_status": data.get('hr_status', ''),
                "department": data.get('department', ''),
                "title": data.get('title', '')
            })
            
        for u, v, edge_data in subgraph.edges(data=True):
            graph_data['edges'].append({
                "from": u,
                "to": v,
                "type": edge_data.get('type', '')
            })
            
    return jsonify({
        "metadata": user_meta,
        "risk_details": risk_data,
        "events": user_events,
        "graph": graph_data
    })

@app.route('/api/incidents')
def get_incidents():
    _, _, _, _, _, clustered_incidents = load_data()
    return jsonify(clustered_incidents)

@app.route('/api/heatmap')
def get_heatmap():
    df_id, _, df_map, _, risk_report, _ = load_data()
    if df_id is None:
        return jsonify([])
        
    departments = ["Engineering", "Marketing", "IT Security", "HR", "Finance", "Sales"]
    platforms = ["AD", "AWS", "Okta"]
    
    risk_dict = {u['emp_id']: u for u in risk_report}
    
    heatmap_matrix = []
    for dept in departments:
        dept_data = {"department": dept}
        for plat in platforms:
            status_col = f"{plat.lower()}_status"
            id_col = f"{plat.lower()}_id"
            
            # Filter users in this department with an active account on this platform
            dept_users = df_id[(df_id['department'] == dept) & (df_id[status_col] == 'Active')]
            user_count = len(dept_users)
            
            # Average risk score
            total_risk = 0.0
            admin_count = 0
            
            for _, row in dept_users.iterrows():
                emp_id = row['emp_id']
                total_risk += risk_dict.get(emp_id, {}).get('hybrid_risk_score', 0.0)
                
                # Check for admin mapping in group_mappings
                acct_id = row[id_col]
                if acct_id and df_map is not None:
                    # Admin groups defined in simulation: ad_groups[:2], aws_roles[:2], okta_groups[:2]
                    # i.e., ad_group_1, ad_group_2, aws_role_1, aws_role_2, okta_group_1, okta_group_2
                    admin_groups = ["ad_group_1", "ad_group_2", "aws_role_1", "aws_role_2", "okta_group_1", "okta_group_2"]
                    is_admin = df_map[(df_map['source_id'] == acct_id) & (df_map['target_id'].isin(admin_groups))]
                    if not is_admin.empty:
                        admin_count += 1
                        
            avg_risk = round(total_risk / user_count, 2) if user_count > 0 else 0.0
            
            dept_data[plat] = {
                "active_accounts": user_count,
                "avg_risk_score": avg_risk,
                "admin_accounts": admin_count
            }
        heatmap_matrix.append(dept_data)
        
    return jsonify(heatmap_matrix)

@app.route('/api/remediate/<incident_id>', methods=['POST'])
def remediate_incident(incident_id):
    """
    Executes a real remediation routine on the CSV files based on the incident type,
    then triggers the risk scorer & incident builder pipeline.
    """
    df_id, df_perm, df_map, _, risk_report, clustered_incidents = load_data()
    if df_id is None:
        return jsonify({"success": False, "error": "Database error"}), 500
        
    # Find the incident
    incident = next((inc for inc in clustered_incidents if inc['incident_id'] == incident_id), None)
    if not incident:
        return jsonify({"success": False, "error": f"Incident {incident_id} not found"}), 404
        
    affected_users = incident.get('affected_users', [])
    affected_emp_ids = [u['emp_id'] for u in affected_users]
    
    remediation_logs = []
    
    title = incident.get('title', '')
    
    if "Orphaned Account" in title:
        # NIST AC-2: Set AD/AWS/Okta account status to Disabled for terminated users
        for emp_id in affected_emp_ids:
            df_id.loc[df_id['emp_id'] == emp_id, ['ad_status', 'aws_status', 'okta_status']] = 'Disabled'
            remediation_logs.append(f"Lifecycle Lockdown: Set status to Disabled for all accounts belonging to Terminated employee {emp_id}")
            
    elif "Excessive Cross-Platform" in title:
        # NIST AC-6: Remove admin group mappings for Marketing/non-IT users
        admin_groups = ["ad_group_1", "ad_group_2", "aws_role_1", "aws_role_2", "okta_group_1", "okta_group_2"]
        for emp_id in affected_emp_ids:
            # Find user account IDs
            user_row = df_id[df_id['emp_id'] == emp_id]
            if not user_row.empty:
                row = user_row.iloc[0]
                acct_ids = [row['ad_id'], row['aws_id'], row['okta_id']]
                acct_ids = [a for a in acct_ids if a]
                
                # Drop rows where source_id is one of these accounts and target is an admin group
                before_len = len(df_map)
                df_map = df_map[~(df_map['source_id'].isin(acct_ids) & df_map['target_id'].isin(admin_groups))]
                after_len = len(df_map)
                
                removed = before_len - after_len
                remediation_logs.append(f"Least Privilege Enforcement: Revoked {removed} administrative group entitlements for Marketing employee {emp_id}")
                
    elif "Credential Abuse" in title or "Privilege Escalation" in title or "Anomalous Behavioral" in title:
        # Security Incident Response: Lock accounts (disable AD, AWS, Okta statuses)
        for emp_id in affected_emp_ids:
            df_id.loc[df_id['emp_id'] == emp_id, ['ad_status', 'aws_status', 'okta_status']] = 'Disabled'
            remediation_logs.append(f"Incident Response: Suspended all AD/AWS/Okta accounts for compromised employee {emp_id}")
            
    # Save modified DataFrames
    df_id.to_csv(IDENTITIES_CSV, index=False)
    df_map.to_csv(MAPPINGS_CSV, index=False)
    
    # Run pipeline to recalculate scores and update JSONs
    remediation_logs.append("Running risk scoring ML engine (Isolation Forest)...")
    remediation_logs.append("Regenerating compliance anomaly report and incident clusters...")
    
    pipeline_success = run_pipeline()
    if pipeline_success:
        remediation_logs.append("Remediation execution successfully processed and metrics updated!")
    else:
        remediation_logs.append("ERROR: Risk scorer pipeline failed. Check backend logs.")
        
    return jsonify({
        "success": pipeline_success,
        "logs": remediation_logs,
        "incident_id": incident_id
    })

@app.route('/api/run-simulation', methods=['POST'])
def run_simulation():
    """Runs simulate_data.py, followed by risk_scorer.py and incident_generator.py to reset/simulate database."""
    try:
        logs = ["Resetting simulation database..."]
        # Run simulate_data.py
        subprocess.run([sys.executable, "simulate_data.py"], check=True)
        logs.append("Generated 300 identities, 150 group mappings, and 800 audit events.")
        
        # Run risk_scorer.py & incident_generator.py
        run_pipeline()
        logs.append("Re-calculated hybrid risk scores & incident clusters.")
        logs.append("Database successfully reset to initial simulation state!")
        
        return jsonify({
            "success": True,
            "logs": logs
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

if __name__ == '__main__':
    # Force run the pipeline on startup to ensure files are fresh and matching
    print("Initiating SprawlBlock backend pipeline...")
    run_pipeline()
    print("Pipeline run completed. Starting Flask server...")
    app.run(host='127.0.0.1', port=5000, debug=True)
