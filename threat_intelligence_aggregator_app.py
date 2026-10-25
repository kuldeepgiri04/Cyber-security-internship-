import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import json

# Page Configuration
st.set_page_config(
    page_title="Threat Intelligence Aggregator",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Threat Intelligence Aggregator")
st.markdown("Query Indicators of Compromise (IoCs) across **VirusTotal** and **AlienVault OTX** in real-time.")

# Sidebar - API Configurations
st.sidebar.header("🔑 API Configurations")
vt_api_key = st.sidebar.text_input("VirusTotal API Key", type="password")
otx_api_key = st.sidebar.text_input("AlienVault OTX API Key", type="password")

st.sidebar.markdown("---")
st.sidebar.info(
    "**Note:** Enter your free API keys to fetch live data. If left empty, "
    "the application will use mock demonstration data for presentation."
)

# Functions for Threat Intelligence
def query_virustotal(ioc, ioc_type, api_key):
    if not api_key:
        # Mock Data Response
        return {
            "status": "Success (Mock)",
            "malicious": 14,
            "suspicious": 2,
            "harmless": 50,
            "reputation": -12,
            "tags": ["phishing", "trojan", "executable"]
        }
    
    headers = {"x-apikey": api_key}
    endpoint = ""
    if ioc_type == "IP Address":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "Domain":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "File Hash (SHA256/MD5)":
        endpoint = f"https://www.virustotal.com/api/v3/files/{ioc}"
        
    try:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            data = response.json()['data']['attributes']
            stats = data['last_analysis_stats']
            return {
                "status": "Success",
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "reputation": data.get('reputation', 0),
                "tags": data.get('tags', [])
            }
        else:
            return {"error": f"VirusTotal API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_alienvault(ioc, ioc_type, api_key):
    if not api_key:
        # Mock Data Response
        return {
            "status": "Success (Mock)",
            "pulse_count": 8,
            "threat_score": 75,
            "pulses": ["APT29 Activity", "Phishing Campaign Q3", "Ransomware C2"]
        }
    
    headers = {"X-OTX-API-KEY": api_key}
    section = "IPv4" if ioc_type == "IP Address" else ("domain" if ioc_type == "Domain" else "file")
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc}/general"
    
    try:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            data = response.json()
            pulse_info = [p['name'] for p in data.get('pulse_info', {}).get('pulses', [])[:5]]
            return {
                "status": "Success",
                "pulse_count": data.get('pulse_info', {}).get('count', 0),
                "threat_score": min(100, data.get('pulse_info', {}).get('count', 0) * 10),
                "pulses": pulse_info
            }
        else:
            return {"error": f"AlienVault API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# User Input Interface
st.subheader("🔍 Query Indicator of Compromise")
col1, col2 = st.columns([1, 3])

with col1:
    ioc_type = st.selectbox("Select IoC Type", ["IP Address", "Domain", "File Hash (SHA256/MD5)"])

with col2:
    ioc_input = st.text_input("Enter IoC Value", placeholder="e.g., 8.8.8.8, malicious-domain.com, or hash")

btn_search = st.button("Analyze Threat Intelligence", type="primary")

if btn_search and ioc_input:
    st.divider()
    st.subheader(f"Analysis Results for: `{ioc_input}`")
    
    with st.spinner("Fetching data from intelligence feeds..."):
        vt_res = query_virustotal(ioc_input, ioc_type, vt_api_key)
        otx_res = query_alienvault(ioc_input, ioc_type, otx_api_key)
        
    c1, c2 = st.columns(2)
    
    # VirusTotal Results Display
    with c1:
        st.markdown("### 🦠 VirusTotal Intelligence")
        if "error" in vt_res:
            st.error(vt_res["error"])
        else:
            st.metric("Malicious Detections", vt_res["malicious"])
            st.metric("Reputation Score", vt_res["reputation"])
            
            # Donut Chart for Analysis Stats
            fig_data = pd.DataFrame({
                "Category": ["Malicious", "Suspicious", "Harmless"],
                "Count": [vt_res["malicious"], vt_res["suspicious"], vt_res["harmless"]]
            })
            fig = px.pie(fig_data, values='Count', names='Category', color='Category',
                         color_discrete_map={'Malicious':'red', 'Suspicious':'orange', 'Harmless':'green'},
                         hole=0.4, title="Analysis Detection Ratio")
            st.plotly_chart(fig, use_container_width=True)
            
            if vt_res.get("tags"):
                st.write("**Associated Tags:**", ", ".join(vt_res["tags"]))

    # AlienVault Results Display
    with c2:
        st.markdown("### 👽 AlienVault OTX Intelligence")
        if "error" in otx_res:
            st.error(otx_res["error"])
        else:
            st.metric("Related Threat Pulses", otx_res["pulse_count"])
            st.metric("Calculated Threat Score", f"{otx_res['threat_score']}/100")
            
            st.subheader("Top Associated Threat Pulses")
            if otx_res.get("pulses"):
                for pulse in otx_res["pulses"]:
                    st.warning(f"⚠️ {pulse}")
            else:
                st.info("No related public threat pulses found.")
                
    st.divider()
    st.subheader("📋 Consolidated Summary")
    
    # Severity assessment logic
    total_malicious = vt_res.get("malicious", 0)
    pulse_count = otx_res.get("pulse_count", 0)
    
    if total_malicious > 5 or pulse_count > 5:
        st.error("🚨 HIGH RISK IOC: Strong indicators of malicious activity detected across threat feeds.")
    elif total_malicious > 0 or pulse_count > 0:
        st.warning("⚠️ MEDIUM RISK IOC: Suspicious signatures or limited detections identified.")
    else:
        st.success("✅ LOW RISK / CLEAN IOC: No major threat signatures detected.")

elif btn_search and not ioc_input:
    st.warning("Please enter a valid IoC value before searching.")