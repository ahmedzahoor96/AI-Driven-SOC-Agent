# AI-Driven SOC Agent: Autonomous Alert Triage Pipeline

## 📌 Project Overview
Traditional security operations are reactive and manual, leading to alert fatigue and high Mean Time to Respond (MTTR). This project transforms a standard Wazuh SIEM deployment into an autonomous, AI-driven Security Operations Center (SOC). 

By utilizing the Model Context Protocol (MCP) and a locally hosted LLM (Llama 3.2), this system actively tails live SIEM logs, autonomously queries threat intelligence (VirusTotal), and generates professional, actionable Incident Response tickets in milliseconds—completely isolating sensitive log data from public AI APIs.

## 🏗️ System Architecture
* **SIEM Layer:** Wazuh Manager (Ubuntu environment) logging network and host-based events.
* **Orchestration Layer:** Custom Python daemons tailing `/var/ossec/logs/alerts/alerts.json` in real-time.
* **Agentic Framework:** FastMCP server exposing custom threat intelligence APIs to the LLM.
* **AI Brain:** Meta's Llama 3.2 (3B) running locally via Ollama on a Windows host for hardware acceleration.

## ⚙️ Core Files
* `live_soc_agent.py`: The main daemon that runs continuously, catching Level 5+ Wazuh alerts, extracting Attacker IPs, and triggering the LLM.
* `mcp_server.py`: The MCP bridge that provides the AI with the `check_ip_reputation` tool using the VirusTotal API.
* `soc_agent.py`: A testing script used to validate the pipeline with simulated alert data.
* `AI_Security_Automation_Detailed_Report.pdf`: Comprehensive project documentation, including architecture diagrams and live brute-force attack simulations.

## 🚀 Live Demonstration
The system successfully detects simulated SSH brute-force attacks and suspicious outbound connections. Upon detection, it extracts the target IP, queries threat intel, and generates an IR ticket containing:
1. Executive Summary
2. Threat Assessment
3. Remediation Steps (e.g., firewall blocking, host isolation)
