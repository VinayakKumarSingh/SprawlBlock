import pandas as pd
import networkx as nx
from datetime import datetime, timezone

def build_identity_graph(identities_path, permissions_path, mappings_path):
    """
    Builds a unified directed graph mapping human identities to their downstream accounts, groups, and permissions.
    """
    G = nx.DiGraph()

    # Load DataFrames
    df_identities = pd.read_csv(identities_path).fillna('')
    df_permissions = pd.read_csv(permissions_path).fillna('')
    df_mappings = pd.read_csv(mappings_path).fillna('')

    # 1. Process Identities & Accounts
    for _, row in df_identities.iterrows():
        emp_id = row['emp_id']
        
        # Add Identity Node
        G.add_node(
            emp_id, 
            type='identity', 
            hr_status=row['hr_status'], 
            department=row['department'], 
            title=row['title']
        )
        
        # Add Account Nodes and link Identity -> Account
        accounts = [
            ('AD', row['ad_id'], row['ad_status']),
            ('AWS', row['aws_id'], row['aws_status']),
            ('Okta', row['okta_id'], row['okta_status'])
        ]
        
        for platform, acct_id, status in accounts:
            if acct_id:
                G.add_node(acct_id, type='account', platform=platform, status=status)
                G.add_edge(emp_id, acct_id, type='identity_to_account')

    # 2. Process Permissions (Groups -> Terminal Permission nodes)
    for _, row in df_permissions.iterrows():
        entity_id = row['entity_id']
        platform = row['platform']
        perm_level = row['permission_level']
        
        # Ensure the group/role node exists
        if not G.has_node(entity_id):
            G.add_node(entity_id, type='group', platform=platform)
            
        # Create unique terminal permission node
        perm_node_id = f"{platform}_{perm_level}"
        if not G.has_node(perm_node_id):
            G.add_node(perm_node_id, type='permission')
            
        # Link Group/Role -> Permission
        G.add_edge(entity_id, perm_node_id, type='entitlement')

    # 3. Process Group Mappings (Source -> Target)
    for _, row in df_mappings.iterrows():
        source_id = row['source_id']
        target_id = row['target_id']
        platform = row['platform']
        
        # Ensure nodes exist (useful for implicit groups)
        if not G.has_node(source_id):
            G.add_node(source_id, type='group', platform=platform)
        if not G.has_node(target_id):
            G.add_node(target_id, type='group', platform=platform)
            
        # Link Source -> Target
        G.add_edge(source_id, target_id, type='mapping', platform=platform)

    return G

def calculate_effective_privileges(G, emp_id):
    """
    Traverses the graph to find all terminal permission nodes reachable from an emp_id.
    Returns a dictionary of platform -> list of permissions.
    """
    if not G.has_node(emp_id):
        return {}

    effective_privs = {}
    
    # Get all nodes reachable from the emp_id
    reachable_nodes = nx.descendants(G, emp_id)
    
    # Filter for permission nodes
    for node in reachable_nodes:
        if G.nodes[node].get('type') == 'permission':
            # Format: PLATFORM_LEVEL
            parts = str(node).split('_', 1)
            if len(parts) == 2:
                platform, level = parts
                if platform not in effective_privs:
                    effective_privs[platform] = set()
                effective_privs[platform].add(level)
                
    # Convert sets to lists
    return {p: list(levels) for p, levels in effective_privs.items()}

def detect_cross_platform_sprawl(G):
    """
    Finds identities where hr_status == 'Terminated' but downstream account nodes are 'Active'.
    """
    flagged_identities = []
    
    # Iterate through all identity nodes
    identity_nodes = [n for n, d in G.nodes(data=True) if d.get('type') == 'identity']
    
    for emp_id in identity_nodes:
        if G.nodes[emp_id].get('hr_status') == 'Terminated':
            active_accounts = []
            
            # Direct successors should be account nodes
            for acct_id in G.successors(emp_id):
                acct_data = G.nodes[acct_id]
                if acct_data.get('type') == 'account' and acct_data.get('status') == 'Active':
                    active_accounts.append({
                        'account_id': acct_id,
                        'platform': acct_data.get('platform')
                    })
                    
            if active_accounts:
                flagged_identities.append({
                    'emp_id': emp_id,
                    'active_accounts': active_accounts
                })
                
    return flagged_identities

def extract_behavioral_features(emp_id, df_events):
    """
    Extracts behavioral features for a single identity from audit events.
    """
    user_events = df_events[df_events['emp_id'] == emp_id].copy()
    
    if user_events.empty:
        return {
            'access_frequency': 0,
            'platform_spread': 0,
            'peak_hour': None,
            'sso_cascade_or_compromise': False
        }
    
    access_freq = len(user_events)
    platform_spread = user_events['platform'].nunique()
    
    user_events['hour'] = user_events['timestamp'].dt.hour
    peak_hour = user_events['hour'].mode()[0] if not user_events['hour'].mode().empty else None
    
    # Velocity/SSO Cascade: Check if logged into 3+ platforms within a 10-minute window
    sso_cascade = False
    if platform_spread >= 3:
        user_events = user_events.sort_values('timestamp')
        for i in range(len(user_events)):
            start_time = user_events.iloc[i]['timestamp']
            end_time = start_time + pd.Timedelta(minutes=10)
            window_events = user_events[(user_events['timestamp'] >= start_time) & (user_events['timestamp'] <= end_time)]
            if window_events['platform'].nunique() >= 3:
                sso_cascade = True
                break
                
    return {
        'access_frequency': access_freq,
        'platform_spread': platform_spread,
        'peak_hour': peak_hour,
        'sso_cascade_or_compromise': sso_cascade
    }

def detect_anomalies(G, df_events, df_identities):
    """
    Combines structural graph entitlements with behavioral data to detect explicit edge cases.
    """
    anomalies = []
    
    # 1. Privilege Escalation & Token/IP Misuse
    escalation_kws = ["AddUserToGroup_DomainAdmins", "AttachUserPolicy_AdministratorAccess", "GrantAdminRole"]
    token_kws = ["API_Call_From_Suspicious_IP", "Use_Expired_Token"]
    
    for _, event in df_events.iterrows():
        action = event['action']
        if any(kw in action for kw in escalation_kws):
            anomalies.append({'emp_id': event['emp_id'], 'type': 'Privilege Escalation', 'reason': f'Action: {action}'})
        elif any(kw in action for kw in token_kws):
            anomalies.append({'emp_id': event['emp_id'], 'type': 'Token/IP Misuse', 'reason': f'Action: {action}'})
            
    # 2. Dormant Admin
    now_dt = pd.Timestamp.now(tz='UTC')
    for _, row in df_identities.iterrows():
        emp_id = row['emp_id']
        last_login_str = row['last_login']
        if pd.notna(last_login_str) and last_login_str != '':
            last_login = pd.to_datetime(last_login_str, utc=True)
            days_since = (now_dt - last_login).days
            if days_since > 30:
                privs = calculate_effective_privileges(G, emp_id)
                # Check if 'Admin' is in any platform's permission list
                if any('Admin' in perms for perms in privs.values()):
                    anomalies.append({
                        'emp_id': emp_id, 
                        'type': 'Dormant Admin', 
                        'reason': f'Inactive for {days_since} days but retains Admin access.'
                    })
                    
    # 3. 2 AM Service Account Spike
    # Define "heavy" as 3+ calls between 1 AM and 4 AM
    spike_events = df_events[(df_events['timestamp'].dt.hour >= 1) & (df_events['timestamp'].dt.hour <= 4)]
    spike_counts = spike_events.groupby('emp_id').size()
    for emp_id, count in spike_counts.items():
        if count >= 3:
            anomalies.append({
                'emp_id': emp_id, 
                'type': '2 AM Spike', 
                'reason': f'Heavy API activity ({count} events) between 1 AM - 4 AM'
            })
            
    return anomalies

if __name__ == "__main__":
    identities_csv = "identities.csv"
    permissions_csv = "permissions.csv"
    mappings_csv = "group_mappings.csv"
    audit_events_csv = "audit_events.csv"
    
    try:
        print("1. Loading Identity Data and Building Entitlement Graph...")
        df_identities = pd.read_csv(identities_csv).fillna('')
        G = build_identity_graph(identities_csv, permissions_csv, mappings_csv)
        
        print(f"   -> Graph Metrics: {nx.number_of_nodes(G)} Nodes | {nx.number_of_edges(G)} Edges")
        
        print("\n2. Ingesting and Mapping Audit Data...")
        df_events = pd.read_csv(audit_events_csv)
        df_events['timestamp'] = pd.to_datetime(df_events['timestamp'], utc=True)
        
        # Build platform_id -> emp_id map
        id_map = {}
        for _, row in df_identities.iterrows():
            if row['ad_id']: id_map[row['ad_id']] = row['emp_id']
            if row['aws_id']: id_map[row['aws_id']] = row['emp_id']
            if row['okta_id']: id_map[row['okta_id']] = row['emp_id']
            
        df_events['emp_id'] = df_events['platform_id'].map(id_map)
        # Drop events that couldn't be mapped to an identity (if any unknowns exist)
        df_events = df_events.dropna(subset=['emp_id'])
        print(f"   -> Successfully mapped {len(df_events)} events to root identities.")
        
        print("\n3. Behavioral Feature Extraction (Sample Over-Privileged User)...")
        marketing_users = [n for n, d in G.nodes(data=True) if d.get('type') == 'identity' and d.get('department') == 'Marketing']
        if marketing_users:
            sample_user = marketing_users[0]
            print(f"   Extracting features for {sample_user}:")
            features = extract_behavioral_features(sample_user, df_events)
            for k, v in features.items():
                print(f"    - {k}: {v}")
                
        print("\n4. Detecting Enterprise-Wide Anomalies (Structural + Behavioral)...")
        anomalies = detect_anomalies(G, df_events, df_identities)
        
        print(f"   -> Detected {len(anomalies)} total anomalies.")
        
        # Group anomalies by type for summary
        df_anomalies = pd.DataFrame(anomalies)
        if not df_anomalies.empty:
            summary = df_anomalies['type'].value_counts()
            for a_type, count in summary.items():
                print(f"      {a_type}: {count}")
                
            # Print a few samples
            print("\n   Sample Anomaly Detections:")
            for idx, a in df_anomalies.head(5).iterrows():
                print(f"    [{a['type']}] {a['emp_id']} - {a['reason']}")

    except FileNotFoundError as e:
        print(f"Error: Required CSV not found. Please ensure simulation has been run. {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
