import json
import os
import time
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

def load_risk_report(filepath):
    """Loads the risk_report.json file."""
    with open(filepath, 'r') as f:
        return json.load(f)

def generate_remediation_narrative(cluster_title, affected_users):
    """
    Generates an LLM-powered executive summary and remediation steps for the incident.
    """
    api_key = os.environ.get('GROQ_API_KEY')
    if not api_key:
        return "Generic Placeholder: Set GROQ_API_KEY to generate LLM narratives."

    try:
        client = Groq(api_key=os.environ.get('GROQ_API_KEY'))
        
        # Ensure you truncate the payload to save token limits
        json_data = json.dumps(affected_users[:5], indent=2)
        
        prompt = (
            f"You are a Cloud Security Architect responding to an incident cluster titled '{cluster_title}'. "
            f"Review this JSON data of affected users: {json_data}. "
            f"Write a 3-paragraph executive summary. "
            f"Paragraph 1: Blast radius and risk summary. "
            f"Paragraph 2: Correlation of their telemetry and graph privileges. "
            f"Paragraph 3: Explicit, copy-pasteable CLI/PowerShell commands to immediately revoke access for the specific platforms involved (AWS, AD, Okta)."
        )
        
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Generic Placeholder: LLM Generation failed ({str(e)})"

def generate_incidents(risk_data):
    """
    Groups high-risk identities into specific incident clusters based on compliance frameworks.
    """
    # 1. Filter Threshold: Only process identities where hybrid_risk_score > 65.0
    high_risk_users = [user for user in risk_data if user.get('hybrid_risk_score', 0) > 65.0]
    
    # Predefined clusters
    clusters = {
        "Orphaned Account & Lifecycle Gaps (NIST AC-2)": [],
        "Excessive Cross-Platform Privilege (NIST AC-6)": [],
        "Credential Abuse & Token Misuse (MITRE T1078/T1550)": [],
        "Privilege Escalation Activity (MITRE T1098)": [],
        "Anomalous Behavioral Activity (ML-Detected)": []
    }
    
    # 2. Deterministic Clustering Logic
    for user in high_risk_users:
        violations = user.get('framework_violations', [])
        
        if not violations:
            clusters["Anomalous Behavioral Activity (ML-Detected)"].append(user)
            continue
            
        first_tag = violations[0]
        
        # Map using the first violation tag
        if "AC-2" in first_tag:
            clusters["Orphaned Account & Lifecycle Gaps (NIST AC-2)"].append(user)
        elif "AC-6" in first_tag:
            clusters["Excessive Cross-Platform Privilege (NIST AC-6)"].append(user)
        elif "T1078" in first_tag or "T1550" in first_tag:
            clusters["Credential Abuse & Token Misuse (MITRE T1078/T1550)"].append(user)
        elif "T1098" in first_tag:
            clusters["Privilege Escalation Activity (MITRE T1098)"].append(user)
        else:
            clusters["Anomalous Behavioral Activity (ML-Detected)"].append(user)
            
    # 3. Incident Formatting & Export
    incidents = []
    incident_counter = 101
    
    for title, users in clusters.items():
        if not users:
            continue  # Ignore empty clusters
            
        # Determine Severity: CRITICAL if any user has hybrid_risk_score > 85, else HIGH
        severity = "HIGH"
        if any(u.get('hybrid_risk_score', 0) > 85.0 for u in users):
            severity = "CRITICAL"
            
        llm_narrative = generate_remediation_narrative(title, users)
        time.sleep(3)
            
        incident = {
            "incident_id": f"INC-{incident_counter}",
            "title": title,
            "severity": severity,
            "affected_identities_count": len(users),
            "llm_executive_summary": llm_narrative,
            "affected_users": users
        }
        incidents.append(incident)
        incident_counter += 1
        
    return incidents

def main():
    risk_file = "risk_report.json"
    output_file = "clustered_incidents.json"
    
    try:
        print(f"Loading {risk_file}...")
        risk_data = load_risk_report(risk_file)
        
        print("Clustering high-risk identities and generating LLM narratives...")
        incidents = generate_incidents(risk_data)
        
        # Save output
        with open(output_file, 'w') as f:
            json.dump(incidents, f, indent=4)
            
        print(f"\nSuccessfully generated {output_file}!")
        print("\n--- INCIDENT SUMMARY ---")
        print(f"Total Incidents Created: {len(incidents)}\n")
        
        for i, inc in enumerate(incidents):
            print(f"[{inc['incident_id']}] {inc['severity']} | {inc['title']}")
            print(f"    Affected Users: {inc['affected_identities_count']}")
            if i == 0:
                print("\n    [Sample LLM Narrative]")
                snippet = inc['llm_executive_summary'][:300] + "..." if len(inc['llm_executive_summary']) > 300 else inc['llm_executive_summary']
                print(f"    {snippet}\n")
            print("-" * 50)
            
    except FileNotFoundError:
        print(f"Error: '{risk_file}' not found. Please ensure risk_scorer.py has been run.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
