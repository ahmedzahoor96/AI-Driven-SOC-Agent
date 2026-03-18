from mcp.server.fastmcp import FastMCP
import requests

# 1. Initialize the MCP Server
mcp = FastMCP("SOC_Agent_Server")

# Replace this with your actual VirusTotal API Key if running locally. 
# Keep as placeholder for GitHub!
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"

# 2. Define the Tool for the LLM
@mcp.tool()
def check_ip_reputation(ip_address: str) -> str:
    """
    Check an IP address against VirusTotal to see if it is malicious.
    The LLM will use this tool when it sees a suspicious IP in the Wazuh logs.
    """
    print(f"\n[+] AI Agent triggered IP check for: {ip_address}")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            # Format the output for the LLM to read
            if malicious > 0 or suspicious > 0:
                result = f"ALERT: IP {ip_address} flagged as Malicious by {malicious} vendors."
            else:
                result = f"SAFE: IP {ip_address} appears clean."
                
            print(f"[>] Result sent back to LLM: {result}")
            return result
        else:
            return f"Error: VirusTotal API returned status code {response.status_code}"
    except Exception as e:
        return f"Error connecting to Threat Intel: {str(e)}"

# 3. Run the Server
if __name__ == "__main__":
    print("Starting SOC MCP Server... Waiting for LLM requests.")
    mcp.run()
