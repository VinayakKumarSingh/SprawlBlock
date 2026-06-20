import pandas as pd
import numpy as np
import json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

# Import core functions from our graph engine
from graph_engine import (
    build_identity_graph,
    calculate_effective_privileges,
    extract_behavioral_features,
    detect_anomalies,
    detect_cross_platform_sprawl
)

def build_feature_matrix(G, df_events, df_identities):
    """
    Constructs the numerical feature matrix for machine learning.
    Calculates the privilege_to_usage_ratio.
    """
    feature_data = []
    
    # Iterate through every human identity
    for _, row in df_identities.iterrows():
        emp_id = row['emp_id']
        
        # Extract behavioral features
        b_features = extract_behavioral_features(emp_id, df_events)
        access_freq = b_features.get('access_frequency', 0)
        platform_spread = b_features.get('platform_spread', 0)
        
        # Calculate effective privileges
        privs = calculate_effective_privileges(G, emp_id)
        # Total number of terminal permission nodes across all platforms
        total_privs = sum(len(perms) for perms in privs.values())
        
        # Calculate Privilege-to-Usage Ratio
        if access_freq == 0:
            # Explicitly set to 0.0 to avoid synthetic outliers skewing the ML model.
            # Inactive accounts are handled deterministically via flat penalties (NIST AC-2).
            priv_to_usage_ratio = 0.0
        else:
            priv_to_usage_ratio = float(total_privs) / float(access_freq)
            
        feature_data.append({
            'emp_id': emp_id,
            'access_frequency': access_freq,
            'platform_spread': platform_spread,
            'privilege_to_usage_ratio': priv_to_usage_ratio,
            'total_privileges': total_privs
        })
        
    return pd.DataFrame(feature_data)

def generate_ml_scores(df_features):
    """
    Fits an Isolation Forest to establish normal behavior and generates a 0-100 ml_risk_score.
    Applies log transformations to right-skewed features for better anomaly detection accuracy.
    """
    X = df_features[['access_frequency', 'platform_spread', 'privilege_to_usage_ratio']].copy()
    
    # Log-transform right-skewed features to prevent extreme outliers from dominating the tree splits
    X['access_frequency'] = np.log1p(X['access_frequency'])
    X['privilege_to_usage_ratio'] = np.log1p(X['privilege_to_usage_ratio'])
    
    # Initialize Isolation Forest (contamination=0.15 as requested)
    clf = IsolationForest(contamination=0.15, random_state=42)
    clf.fit(X)
    
    # Get anomaly scores: lower score means more anomalous.
    scores = clf.decision_function(X)
    
    # Normalize inverted scores to 0-100
    # To prevent 'least anomalous' from always being 0 and 'most anomalous' always being 100 in a safe batch,
    # we could theoretically use fixed thresholds. For this scope, MinMaxScaler is sufficient, but we
    # apply it over the mathematically smoothed decision boundaries.
    scaler = MinMaxScaler(feature_range=(0, 100))
    inverted_scores = -1 * scores.reshape(-1, 1)
    ml_risk_scores = scaler.fit_transform(inverted_scores).flatten()
    
    df_features['ml_risk_score'] = ml_risk_scores
    return df_features

def map_compliance_frameworks(df_features, G, df_events, df_identities):
    """
    Fetches deterministic anomalies and maps them to compliance frameworks.
    """
    framework_violations = {emp_id: [] for emp_id in df_features['emp_id']}
    
    # 1. Cross-Platform Sprawl
    sprawls = detect_cross_platform_sprawl(G)
    for sprawl in sprawls:
        emp_id = sprawl['emp_id']
        if emp_id in framework_violations:
            framework_violations[emp_id].append("NIST AC-2 / CIS 5")
            
    # 2. General Anomalies
    anomalies = detect_anomalies(G, df_events, df_identities)
    for anomaly in anomalies:
        emp_id = anomaly['emp_id']
        a_type = anomaly['type']
        
        if emp_id in framework_violations:
            if a_type == 'Dormant Admin':
                framework_violations[emp_id].append("NIST AC-2 / CIS 5")
            elif a_type in ['Token/IP Misuse', '2 AM Spike']:
                framework_violations[emp_id].append("MITRE T1078 / MITRE T1550")
            elif a_type == 'Privilege Escalation':
                framework_violations[emp_id].append("MITRE T1098")
                
    # 3. ML Anomaly + High Privilege-to-Usage Ratio
    # Calculate the ratio_threshold ONLY using active, privileged users:
    active_users = df_features[(df_features['access_frequency'] > 0) & (df_features['total_privileges'] > 0)]
    ratio_threshold = active_users['privilege_to_usage_ratio'].quantile(0.75) if not active_users.empty else 1.0
    
    # Ensure an absolute minimum floor so healthy ratios aren't flagged:
    ratio_threshold = max(ratio_threshold, 1.0)
    
    for _, row in df_features.iterrows():
        emp_id = row['emp_id']
        # Check if the user is an ML anomaly OR simply highly over-privileged:
        if (row['ml_risk_score'] > 70 and row['privilege_to_usage_ratio'] >= ratio_threshold) or (row['privilege_to_usage_ratio'] >= 2.0):
            framework_violations[emp_id].append("NIST AC-6 / GDPR Art 5")
            
    # Deduplicate lists
    for emp_id in framework_violations:
        framework_violations[emp_id] = list(set(framework_violations[emp_id]))
        
    return framework_violations

def calculate_hybrid_risk(df_features, framework_violations):
    """
    Combines ML risk with deterministic penalties.
    """
    final_report = []
    
    for _, row in df_features.iterrows():
        emp_id = row['emp_id']
        ml_score = row['ml_risk_score']
        violations = framework_violations.get(emp_id, [])
        
        penalty = 0
        for violation in violations:
            if "MITRE T1098" in violation:
                penalty += 40  # Privilege Escalation is high risk
            elif "MITRE" in violation:
                penalty += 30  # Token misuse / 2 AM spike
            elif "NIST AC-2" in violation:
                penalty += 25  # Sprawl / Dormant Admin
            elif "NIST AC-6" in violation:
                penalty += 20  # Over-privileged (ML based)
                
        hybrid_score = ml_score + penalty
        hybrid_score = min(hybrid_score, 100.0)  # Cap at 100
        
        final_report.append({
            'emp_id': emp_id,
            'hybrid_risk_score': round(hybrid_score, 2),
            'ml_risk_score': round(ml_score, 2),
            'features': {
                'access_frequency': int(row['access_frequency']),
                'platform_spread': int(row['platform_spread']),
                'privilege_to_usage_ratio': round(row['privilege_to_usage_ratio'], 3),
                'total_privileges': int(row['total_privileges'])
            },
            'framework_violations': violations
        })
        
    # Sort descending by hybrid_risk_score
    final_report.sort(key=lambda x: x['hybrid_risk_score'], reverse=True)
    return final_report

if __name__ == "__main__":
    identities_csv = "identities.csv"
    permissions_csv = "permissions.csv"
    mappings_csv = "group_mappings.csv"
    audit_events_csv = "audit_events.csv"
    
    print("1. Loading Identity Data and Building Graph...")
    df_identities = pd.read_csv(identities_csv).fillna('')
    G = build_identity_graph(identities_csv, permissions_csv, mappings_csv)
    
    print("2. Ingesting Audit Data...")
    df_events = pd.read_csv(audit_events_csv)
    df_events['timestamp'] = pd.to_datetime(df_events['timestamp'], utc=True)
    
    # Build platform_id -> emp_id map
    id_map = {}
    for _, row in df_identities.iterrows():
        if row['ad_id']: id_map[row['ad_id']] = row['emp_id']
        if row['aws_id']: id_map[row['aws_id']] = row['emp_id']
        if row['okta_id']: id_map[row['okta_id']] = row['emp_id']
    df_events['emp_id'] = df_events['platform_id'].map(id_map)
    df_events = df_events.dropna(subset=['emp_id'])
    
    print("3. Performing Feature Engineering...")
    df_features = build_feature_matrix(G, df_events, df_identities)
    
    print("4. Training Isolation Forest ML Model...")
    df_features = generate_ml_scores(df_features)
    
    print("5. Mapping Compliance Frameworks...")
    framework_violations = map_compliance_frameworks(df_features, G, df_events, df_identities)
    
    print("6. Calculating Hybrid Risk Scores...")
    final_report = calculate_hybrid_risk(df_features, framework_violations)
    
    # Save to JSON
    output_file = "risk_report.json"
    with open(output_file, 'w') as f:
        json.dump(final_report, f, indent=4)
        
    print(f"\nSuccessfully generated {output_file}!")
    
    print("\n--- TOP 5 RISKIEST IDENTITIES ---")
    for i, report in enumerate(final_report[:5]):
        print(f"#{i+1}: {report['emp_id']} | Hybrid Score: {report['hybrid_risk_score']} | ML Score: {report['ml_risk_score']}")
        print(f"    Violations: {', '.join(report['framework_violations']) if report['framework_violations'] else 'None'}")
        print(f"    Ratio: {report['features']['privilege_to_usage_ratio']} (Freq: {report['features']['access_frequency']}, Privs: {report['features']['total_privileges']})")
        print("-" * 50)
