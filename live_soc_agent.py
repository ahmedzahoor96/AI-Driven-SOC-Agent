import json
import subprocess
from mcp_server import check_ip_reputation
from ollama import Client

# Connect to your distributed Llama 3.2 on Windows
OLLAMA_HOST = "http://YOUR_WINDOWS_IP:11434"
client = Client(host=OLLAMA_HOST)

# The live Wazuh alert stream
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

def follow_alerts():
    print(f"[*] Hooking into Wazuh live alert stream: {ALERTS_FILE}")
    print("[*] Listening for new high-severity network alerts...\n")
    
    # Use the Linux 'tail' command to read the file continuously
    f = subprocess.Popen(['tail', '-F', ALERTS_FILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    while True:
        line = f.stdout.readline()
        if not line:
            continue
            
        try:
            alert = json.loads(line)
            rule_level = alert.get("rule", {}).get("level", 0)
            
            # Extract the attacker's IP address (Wazuh sometimes uses 'srcip' or 'src_ip')
            src_ip = alert.get("data", {}).get("srcip") or alert.get("data", {}).get("src_ip")
            
            # Filter: Only trigger on alerts level 5 or higher that have a source IP
            if rule_level >= 5 and src_ip:
                description = alert.get('rule', {}).get('description', 'Unknown Alert')
                agent_name = alert.get('agent', {}).get('name', 'Unknown Agent')
                
                print(f"\n[!] WAZUH ALERT CAUGHT LIVE: Level {rule_level} - {description}")
                print(f"[*] Target Endpoint: {agent_name}")
                print(f"[*] Attacker IP Extracted: {src_ip}")
                
                investigate_and_report(src_ip, description, agent_name)
                
                print("\n[*] Investigation complete. Resuming Wazuh alert monitoring...")
                
        except json.JSONDecodeError:
            continue

def investigate_and_report(ip, description, agent):
    print(f"[*] Agent autonomously querying Threat Intel for IP: {ip}...")
    tool_result = check_ip_reputation(ip)
    
    prompt = f"""
    You are a Senior SOC Analyst. A live alert just triggered on our Wazuh SIEM.
    
    Alert Details:
    - Description: {description}
    - Affected Agent: {agent}
    - Attacker IP: {ip}
    - MCP Threat Intel Tool Result: {tool_result}
    
    Write a highly professional, concise Incident Response ticket. Include:
    1. Executive Summary
    2. Threat Assessment
    3. Remediation Steps
    """
    
    print("[*] Context gathered. Llama 3.2 is generating the IR Ticket...")
    print("=" * 60)
    response = client.generate(model='llama3.2', prompt=prompt)
    print(response['response'])
    print("=" * 60)

if __name__ == "__main__":
    follow_alerts()
