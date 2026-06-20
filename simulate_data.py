import pandas as pd
# pyrefly: ignore [missing-import]
import numpy as np
import random
from datetime import datetime, timedelta
import uuid

# Configuration Constraints
NUM_IDENTITIES = 300
NUM_MAPPINGS = 150
NUM_AUDIT_EVENTS = 800

# Mathematically determined anomaly sizes
NUM_ORPHANED = int(NUM_IDENTITIES * 0.12)  # 36
NUM_NESTED = int(NUM_MAPPINGS * 0.10)      # 15
NUM_ESCALATION = int(NUM_AUDIT_EVENTS * 0.05) # 40

def random_date(days_back=30):
    """Generate a random timestamp within the last `days_back` days."""
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
        
        # Inject Orphaned Accounts (12%)
        if i <= NUM_ORPHANED:
            hr_status = "Terminated"
            ad_status = "Disabled"
            # To be orphaned, it must remain active in Okta or AWS
            aws_status = random.choice(["Active", "Disabled"])
            okta_status = "Active" if aws_status == "Disabled" else random.choice(["Active", "Disabled"])
        else:
            # Normal logic
            hr_status = random.choices(["Active", "Terminated"], weights=[0.9, 0.1])[0]
            if hr_status == "Terminated":
                ad_status = "Disabled"
                aws_status = "Disabled"
                okta_status = "Disabled"
            else:
                ad_status = "Active"
                aws_status = "Active"
                okta_status = "Active"
                
        identities.append({
            "emp_id": emp_id,
            "hr_status": hr_status,
            "ad_id": ad_id,
            "ad_status": ad_status,
            "aws_id": aws_id,
            "aws_status": aws_status,
            "okta_id": okta_id,
            "okta_status": okta_status
        })
    return pd.DataFrame(identities)

def generate_permissions():
    permissions = []
    # Standard AD groups
    ad_groups = [f"ad_group_{i}" for i in range(1, 21)]
    # AWS roles - First 3 are highly privileged
    aws_roles = [f"aws_role_{i}" for i in range(1, 16)]
    # Okta groups
    okta_groups = [f"okta_group_{i}" for i in range(1, 11)]

    for g in ad_groups:
        permissions.append({"entity_id": g, "platform": "AD", "permission_level": "Read-Only"})
    for r in aws_roles:
        if r in aws_roles[:3]:
            permissions.append({"entity_id": r, "platform": "AWS", "permission_level": "Admin"})
        else:
            permissions.append({"entity_id": r, "platform": "AWS", "permission_level": "PowerUser"})
    for og in okta_groups:
        permissions.append({"entity_id": og, "platform": "Okta", "permission_level": "User"})
        
    return pd.DataFrame(permissions), ad_groups, aws_roles, okta_groups

def generate_group_mappings(df_identities, ad_groups, aws_roles, okta_groups):
    mappings = []
    active_ad_ids = df_identities[df_identities['ad_status'] == 'Active']['ad_id'].tolist()
    active_aws_ids = df_identities[df_identities['aws_status'] == 'Active']['aws_id'].tolist()
    active_okta_ids = df_identities[df_identities['okta_status'] == 'Active']['okta_id'].tolist()

    for i in range(1, NUM_MAPPINGS + 1):
        mapping_id = f"map_{i:03d}"
        
        # Inject Over-privileged via Nesting (10%)
        if i <= NUM_NESTED:
            # Map benign AD group to a highly privileged AWS role
            benign_ad_group = random.choice(ad_groups)
            high_priv_aws_role = random.choice(aws_roles[:3])
            mappings.append({
                "mapping_id": mapping_id,
                "source_id": benign_ad_group,
                "target_id": high_priv_aws_role,
                "platform": "Cross-Platform"
            })
            
            # Ensure there is an identity nested in this AD group to complete the exploit chain
            if active_ad_ids:
                mappings.append({
                    "mapping_id": f"map_{i:03d}_a",
                    "source_id": random.choice(active_ad_ids),
                    "target_id": benign_ad_group,
                    "platform": "AD"
                })
        else:
            # Normal mappings
            platform = random.choice(["AD", "AWS", "Okta"])
            if platform == "AD" and active_ad_ids:
                mappings.append({
                    "mapping_id": mapping_id,
                    "source_id": random.choice(active_ad_ids),
                    "target_id": random.choice(ad_groups),
                    "platform": "AD"
                })
            elif platform == "AWS" and active_aws_ids:
                mappings.append({
                    "mapping_id": mapping_id,
                    "source_id": random.choice(active_aws_ids),
                    "target_id": random.choice(aws_roles[3:]), # Assign to non-admin roles usually
                    "platform": "AWS"
                })
            elif platform == "Okta" and active_okta_ids:
                mappings.append({
                    "mapping_id": mapping_id,
                    "source_id": random.choice(active_okta_ids),
                    "target_id": random.choice(okta_groups),
                    "platform": "Okta"
                })
    
    # We only take exactly NUM_MAPPINGS records, since we appended extra mappings above to complete the chain
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
        "Okta": ["GrantAdminRole", "CreateAPIToken"]
    }

    active_ad_ids = df_identities[df_identities['ad_status'] == 'Active']['ad_id'].tolist()
    active_aws_ids = df_identities[df_identities['aws_status'] == 'Active']['aws_id'].tolist()
    active_okta_ids = df_identities[df_identities['okta_status'] == 'Active']['okta_id'].tolist()
    
    for i in range(1, NUM_AUDIT_EVENTS + 1):
        event_id = str(uuid.uuid4())
        timestamp = random_date().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Inject Privilege Escalation (5%)
        if i <= NUM_ESCALATION:
            platform = random.choice(["AD", "AWS", "Okta"])
            action = random.choice(escalation_actions[platform])
            
            p_id = "unknown"
            if platform == "AD" and active_ad_ids: p_id = random.choice(active_ad_ids)
            elif platform == "AWS" and active_aws_ids: p_id = random.choice(active_aws_ids)
            elif platform == "Okta" and active_okta_ids: p_id = random.choice(active_okta_ids)
            
            audit_events.append({
                "event_id": event_id,
                "timestamp": timestamp,
                "platform_id": p_id,
                "platform": platform,
                "action": action,
                "status": "Success"
            })
        else:
            # Normal events
            platform = random.choice(["AD", "AWS", "Okta"])
            action = random.choice(normal_actions[platform])
            status = random.choices(["Success", "Failure"], weights=[0.95, 0.05])[0]
            
            p_id = "unknown"
            if platform == "AD" and active_ad_ids: p_id = random.choice(active_ad_ids)
            elif platform == "AWS" and active_aws_ids: p_id = random.choice(active_aws_ids)
            elif platform == "Okta" and active_okta_ids: p_id = random.choice(active_okta_ids)
            
            audit_events.append({
                "event_id": event_id,
                "timestamp": timestamp,
                "platform_id": p_id,
                "platform": platform,
                "action": action,
                "status": status
            })

    df_events = pd.DataFrame(audit_events)
    # Shuffle and sort by time
    df_events = df_events.sort_values(by="timestamp").reset_index(drop=True)
    return df_events

def main():
    print("Generating identities...")
    df_identities = generate_identities()
    
    print("Generating permissions...")
    df_permissions, ad_groups, aws_roles, okta_groups = generate_permissions()
    
    print("Generating group mappings...")
    df_mappings = generate_group_mappings(df_identities, ad_groups, aws_roles, okta_groups)
    
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
    escalation_actions_all = ["AddUserToGroup_DomainAdmins", "ResetAdminPassword", "AttachUserPolicy_AdministratorAccess", "CreateRole_HighPriv", "GrantAdminRole", "CreateAPIToken"]
    escalations = df_events[df_events['action'].isin(escalation_actions_all)]

    print(f"\n--- Anomaly Verification ---")
    print(f"Orphaned Accounts: {len(orphaned)} (Expected {NUM_ORPHANED})")
    print(f"Cross-Platform Nesting: {len(nested)} (Expected {NUM_NESTED})")
    print(f"Privilege Escalations: {len(escalations)} (Expected {NUM_ESCALATION})")
    
    # Save files
    df_identities.to_csv("identities.csv", index=False)
    df_permissions.to_csv("permissions.csv", index=False)
    df_mappings.to_csv("group_mappings.csv", index=False)
    df_events.to_csv("audit_events.csv", index=False)
    
    print("\nSuccessfully generated the following files:")
    print(" - identities.csv")
    print(" - permissions.csv")
    print(" - group_mappings.csv")
    print(" - audit_events.csv")

if __name__ == "__main__":
    main()
