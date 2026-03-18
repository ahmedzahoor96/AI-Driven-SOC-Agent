import json
from mcp_server import check_ip_reputation
from ollama import Client

# Connect to the Local LLM on your Windows Host
OLLAMA_HOST = "http://YOUR_WINDOWS_IP:11434"
client = Client(host=OLLAMA_HOST)

def run_soc_investigation():
    # Simulate an incoming alert from Wazuh/Suricata for your Windows 10 endpoint
    print("\n[+] WAZUH ALERT RECEIVED: Suspicious outbound traffic detected.")
    suspicious_ip = "185.156.73.31" # A known test IP we want the AI to investigate
    
    # The Agent uses the MCP Tool you built to gather context automatically
    print(f"[*] Agent is autonomously querying Threat Intel for IP: {suspicious_ip}...")
    tool_result = check_ip_reputation(suspicious_ip)
    
    # Formulate the prompt with the exact context gathered by the tool
    prompt = f"""
    You are a Senior SOC Analyst. You received an alert for a Windows 10 endpoint connecting to a suspicious IP.
    
    Alert Details:
    - Target IP: {suspicious_ip}
    - MCP Threat Intel Tool Result: {tool_result}
    
    Write a highly professional, concise Incident Response ticket. Include:
    1. Executive Summary
    2. Threat Assessment (Is it a false positive or a true threat?)
    3. Remediation Steps (e.g., firewall blocking, host isolation)
    """
    
    print("[*] Context gathered. Llama 3.2 is now generating the Incident Response Ticket...")
    print("=" * 60)
    
    response = client.generate(model='llama3.2', prompt=prompt)
    
    print(response['response'])
    print("\n" + "=" * 60)
    print("[+] Investigation Complete. Ticket logged.")

if __name__ == "__main__":
    run_soc_investigation()
