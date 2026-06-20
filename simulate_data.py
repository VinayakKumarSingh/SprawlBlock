import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import uuid

# Configuration Constraints
NUM_IDENTITIES = 300
NUM_MAPPINGS = 150
NUM_AUDIT_EVENTS = 800

# Identity counts based on prompt percentages
NUM_ORPHANED = int(NUM_IDENTITIES * 0.12)       # 36 identities (12%)
NUM_OVERPRIVILEGED = int(NUM_IDENTITIES * 0.08) # 24 identities (8%)
NUM_LEGIT_HIGH_PRIV = int(NUM_IDENTITIES * 0.15)# 45 identities (15%)

# Audit Event counts
NUM_ESCALATION = int(NUM_AUDIT_EVENTS * 0.05)   # 40 events (5%)
NUM_TOKEN_ABUSE = int(NUM_AUDIT_EVENTS * 0.04)  # 32 events (4%)

def random_date(days_back=30):
    now = datetime.now()
    return now - timedelta(days=random.randint(0, days_back), 
                           hours=random.randint(0, 23), 
                           minutes=random.randint(0, 59))

def generate_identities():
    identities = []
    
    for i in range(1, NUM_IDENTITIES + 1):
        emp_id = f"emp_{i:03d}"
        
        ad_id = f"ad_{emp_id}"
        aws_id = f"aws_{emp_id}"
        okta_id = f"okta_{emp_id}"
        
        # Default initialization
        last_login = random_date(10).strftime("%Y-%m-%dT%H:%M:%SZ")
        termination_date = ""
        department = "Engineering"
        title = "Software Engineer"
        justification = ""
        
        # 1. Orphaned Accounts
        if i <= NUM_ORPHANED:
            hr_status = "Terminated"
            ad_status = "Disabled"
            aws_status = random.choice(["Active", "Disabled"])
            okta_status = "Active" if aws_status == "Disabled" else random.choice(["Active", "Disabled"])
            term_date_obj = random_date(60)
            termination_date = term_date_obj.strftime("%Y-%m-%dT%H:%M:%SZ")
            last_login = (term_date_obj + timedelta(days=random.randint(1, 10))).strftime("%Y-%m-%dT%H:%M:%SZ")
            
        # 2. Over-privileged identities (admin across platforms without justification)
        elif i <= NUM_ORPHANED + NUM_OVERPRIVILEGED:
            hr_status = "Active"
            ad_status, aws_status, okta_status = "Active", "Active", "Active"
            department = "Marketing"
            title = "Marketing Specialist"
            justification = "None"
            
        # 3. Legitimate high-privilege users (On-Call, false positive traps)
        elif i <= NUM_ORPHANED + NUM_OVERPRIVILEGED + NUM_LEGIT_HIGH_PRIV:
            hr_status = "Active"
            ad_status, aws_status, okta_status = "Active", "Active", "Active"
            department = "IT Security"
            title = "On-Call Site Reliability Engineer"
            justification = "Approved role transition / On-Call rotation"
            
        # 4. Normal Activity
        else:
            hr_status = random.choices(["Active", "Terminated"], weights=[0.9, 0.1])[0]
            if hr_status == "Terminated":
                ad_status, aws_status, okta_status = "Disabled", "Disabled", "Disabled"
                term_date_obj = random_date(60)
                termination_date = term_date_obj.strftime("%Y-%m-%dT%H:%M:%SZ")
                last_login = (term_date_obj - timedelta(days=random.randint(1, 10))).strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                ad_status, aws_status, okta_status = "Active", "Active", "Active"
                department = random.choice(["Engineering", "Sales", "HR", "Finance"])
                title = "Employee"
                
        identities.append({
            "emp_id": emp_id,
            "hr_status": hr_status,
            "department": department,
            "title": title,
            "justification": justification,
            "ad_id": ad_id,
            "ad_status": ad_status,
            "aws_id": aws_id,
            "aws_status": aws_status,
            "okta_id": okta_id,
            "okta_status": okta_status,
            "last_login": last_login,
            "termination_date": termination_date
        })
    return pd.DataFrame(identities)

def generate_permissions():
    permissions = []
    ad_groups = [f"ad_group_{i}" for i in range(1, 11)]
    aws_roles = [f"aws_role_{i}" for i in range(1, 11)]
    okta_groups = [f"okta_group_{i}" for i in range(1, 11)]

    for g in ad_groups:
        level = "Admin" if g in ad_groups[:2] else "Read-Only"
        permissions.append({"entity_id": g, "platform": "AD", "permission_level": level})
    for r in aws_roles:
        level = "Admin" if r in aws_roles[:2] else "PowerUser"
        permissions.append({"entity_id": r, "platform": "AWS", "permission_level": level})
    for og in okta_groups:
        level = "Admin" if og in okta_groups[:2] else "User"
        permissions.append({"entity_id": og, "platform": "Okta", "permission_level": level})
        
    return pd.DataFrame(permissions), ad_groups, aws_roles, okta_groups

def generate_group_mappings(df_identities, ad_groups, aws_roles):
    mappings = []
    
    # Mathematical allocation to hit EXACTLY 150 mappings
    NUM_NESTED = 15  # Cross-platform nesting mappings
    
    for i in range(1, NUM_NESTED + 1):
        # Benign AD group to Admin AWS Role
        mappings.append({
            "mapping_id": f"map_{i:03d}",
            "source_id": random.choice(ad_groups[2:]), # Non-admin AD group
            "target_id": random.choice(aws_roles[:2]), # Admin AWS role
            "platform": "Cross-Platform"
        })
        
    current_mapping_id = NUM_NESTED + 1
    
    overpriv_ids = df_identities[df_identities['department'] == 'Marketing']['emp_id'].tolist()
    legit_ids = df_identities[df_identities['department'] == 'IT Security']['emp_id'].tolist()
    
    # We assign overprivileged users Admin on both AD and AWS (2 mappings each)
    for emp_id in overpriv_ids:
        if current_mapping_id > NUM_MAPPINGS: break
        mappings.append({"mapping_id": f"map_{current_mapping_id:03d}", "source_id": f"ad_{emp_id}", "target_id": ad_groups[0], "platform": "AD"})
        current_mapping_id += 1
        
        if current_mapping_id > NUM_MAPPINGS: break
        mappings.append({"mapping_id": f"map_{current_mapping_id:03d}", "source_id": f"aws_{emp_id}", "target_id": aws_roles[0], "platform": "AWS"})
        current_mapping_id += 1
        
    # Assign legitimate high-privilege users Admin on both AD and AWS
    for emp_id in legit_ids:
        if current_mapping_id > NUM_MAPPINGS: break
        mappings.append({"mapping_id": f"map_{current_mapping_id:03d}", "source_id": f"ad_{emp_id}", "target_id": ad_groups[1], "platform": "AD"})
        current_mapping_id += 1
        
        if current_mapping_id > NUM_MAPPINGS: break
        mappings.append({"mapping_id": f"map_{current_mapping_id:03d}", "source_id": f"aws_{emp_id}", "target_id": aws_roles[1], "platform": "AWS"})
        current_mapping_id += 1
        
    # Fallback to fill exactly to 150 if we somehow missed
    active_ad = df_identities[df_identities['ad_status'] == 'Active']['ad_id'].tolist()
    while current_mapping_id <= NUM_MAPPINGS:
        mappings.append({"mapping_id": f"map_{current_mapping_id:03d}", "source_id": random.choice(active_ad), "target_id": random.choice(ad_groups[2:]), "platform": "AD"})
        current_mapping_id += 1
        
    return pd.DataFrame(mappings).head(NUM_MAPPINGS)

def generate_audit_events(df_identities):
    audit_events = []
    
    normal_actions = {
        "AD": ["Login", "ReadShare", "Logoff", "ChangePassword"],
        "AWS": ["AssumeRole", "ReadS3Bucket", "DescribeEC2Instances"],
        "Okta": ["SSOLogin", "ViewDashboard", "UpdateProfile"]
    }
    
    escalation_actions = {
        "AD": ["AddUserToGroup_DomainAdmins", "ResetAdminPassword"],
        "AWS": ["AttachUserPolicy_AdministratorAccess", "CreateRole_HighPriv"],
        "Okta": ["GrantAdminRole"]
    }
    
    token_abuse_actions = {
        "AWS": ["API_Call_From_Suspicious_IP", "Use_Expired_Token", "Anomalous_Mass_S3_Download"],
        "Okta": ["Login_From_New_Country", "Impossible_Travel_Login"]
    }

    active_ad_ids = df_identities[df_identities['ad_status'] == 'Active']['ad_id'].tolist()
    active_aws_ids = df_identities[df_identities['aws_status'] == 'Active']['aws_id'].tolist()
    active_okta_ids = df_identities[df_identities['okta_status'] == 'Active']['okta_id'].tolist()
    
    for i in range(1, NUM_AUDIT_EVENTS + 1):
        event_id = str(uuid.uuid4())
        timestamp = random_date().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # 1. Privilege Escalation (5%)
        if i <= NUM_ESCALATION:
            platform = random.choice(["AD", "AWS", "Okta"])
            action = random.choice(escalation_actions[platform])
            p_id = random.choice(active_ad_ids if platform == "AD" else active_aws_ids if platform == "AWS" else active_okta_ids)
            status = "Success"
            
        # 2. Token / Credential Abuse (4%)
        elif i <= NUM_ESCALATION + NUM_TOKEN_ABUSE:
            platform = random.choice(["AWS", "Okta"])
            action = random.choice(token_abuse_actions[platform])
            p_id = random.choice(active_aws_ids if platform == "AWS" else active_okta_ids)
            status = "Success"
            
        # 3. Normal events
        else:
            platform = random.choice(["AD", "AWS", "Okta"])
            action = random.choice(normal_actions[platform])
            p_id = random.choice(active_ad_ids if platform == "AD" else active_aws_ids if platform == "AWS" else active_okta_ids)
            status = random.choices(["Success", "Failure"], weights=[0.95, 0.05])[0]
            
        audit_events.append({
            "event_id": event_id,
            "timestamp": timestamp,
            "platform_id": p_id,
            "platform": platform,
            "action": action,
            "status": status
        })

    df_events = pd.DataFrame(audit_events)
    df_events = df_events.sort_values(by="timestamp").reset_index(drop=True)
    return df_events

def main():
    print("Generating identities...")
    df_identities = generate_identities()
    
    print("Generating permissions...")
    df_permissions, ad_groups, aws_roles, okta_groups = generate_permissions()
    
    print("Generating group mappings...")
    df_mappings = generate_group_mappings(df_identities, ad_groups, aws_roles)
    
    print("Generating audit events...")
    df_events = generate_audit_events(df_identities)
    
    # Validation checks
    assert len(df_identities) == NUM_IDENTITIES, f"Identities mismatch: {len(df_identities)} != {NUM_IDENTITIES}"
    assert len(df_mappings) == NUM_MAPPINGS, f"Mappings mismatch: {len(df_mappings)} != {NUM_MAPPINGS}"
    assert len(df_events) == NUM_AUDIT_EVENTS, f"Events mismatch: {len(df_events)} != {NUM_AUDIT_EVENTS}"

    # Verify anomalies
    orphaned = df_identities[(df_identities['hr_status'] == 'Terminated') & 
                             ((df_identities['aws_status'] == 'Active') | (df_identities['okta_status'] == 'Active'))]
    nested = df_mappings[df_mappings['platform'] == 'Cross-Platform']
    escalation_actions_all = ["AddUserToGroup_DomainAdmins", "ResetAdminPassword", "AttachUserPolicy_AdministratorAccess", "CreateRole_HighPriv", "GrantAdminRole"]
    token_abuse_all = ["API_Call_From_Suspicious_IP", "Use_Expired_Token", "Anomalous_Mass_S3_Download", "Login_From_New_Country", "Impossible_Travel_Login"]
    
    escalations = df_events[df_events['action'].isin(escalation_actions_all)]
    token_abuse = df_events[df_events['action'].isin(token_abuse_all)]
    overpriv = df_identities[df_identities['department'] == 'Marketing']
    legit_priv = df_identities[df_identities['department'] == 'IT Security']

    print(f"\n--- Anomaly Verification ---")
    print(f"Orphaned/Stale Accounts: {len(orphaned)} (Expected ~10-15%)")
    print(f"Over-privileged (Marketing/Admin): {len(overpriv)} (Expected ~8-12%)")
    print(f"Legitimate High-Priv (IT/On-Call): {len(legit_priv)} (Expected ~15-20%)")
    print(f"Cross-Platform Nesting Mappings: {len(nested)}")
    print(f"Privilege Escalation Events: {len(escalations)} (Expected ~5-8%)")
    print(f"Token/Credential Abuse Events: {len(token_abuse)} (Expected ~3-5%)")
    
    # Save files
    df_identities.to_csv("identities.csv", index=False)
    df_permissions.to_csv("permissions.csv", index=False)
    df_mappings.to_csv("group_mappings.csv", index=False)
    df_events.to_csv("audit_events.csv", index=False)
    
    print("\nSuccessfully generated files locally.")

if __name__ == "__main__":
    main()
