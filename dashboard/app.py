import streamlit as st
import pandas as pd
import json
import time
import altair as alt

st.set_page_config(page_title="Hybrid IDS Monitor", layout="wide")
st.title("🛡️ Hybrid IDS/IPS Real-Time Dashboard")

LOG_FILE = '/var/log/suricata/eve.json'

@st.cache_data(ttl=5)
def load_data():
    alerts =
    flows =
    try:
        with open(LOG_FILE, 'r') as f:
            # tailored for performance, read last 2000 lines
            lines = f.readlines()[-2000:] 
            for line in lines:
                try:
                    e = json.loads(line)
                    if e['event_type'] == 'alert':
                        alerts.append({
                            'Timestamp': e['timestamp'],
                            'Source': e['src_ip'],
                            'Signature': e['alert']['signature'],
                            'Severity': e['alert']['severity']
                        })
                    elif e['event_type'] == 'flow':
                        flows.append({
                            'Timestamp': e['timestamp'],
                            'Bytes': e['flow']['bytes_toserver'] + e['flow']['bytes_toclient'],
                            'App': e.get('app_proto', 'unknown')
                        })
                except:
                    continue
    except FileNotFoundError:
        return pd.DataFrame(), pd.DataFrame()
    
    return pd.DataFrame(alerts), pd.DataFrame(flows)

# Auto-refresh loop
placeholder = st.empty()

while True:
    df_alerts, df_flows = load_data()
    
    with placeholder.container():
        kpi1, kpi2, kpi3 = st.columns(3)
        kpi1.metric("Total Alerts", len(df_alerts))
        kpi2.metric("Monitored Flows", len(df_flows))
        kpi3.metric("Status", "Active 🟢")

        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🚨 Recent Intrusions")
            if not df_alerts.empty:
                st.dataframe(df_alerts.tail(10))
            else:
                st.info("System Secure. No Alerts.")

        with col2:
            st.subheader("📊 Traffic Volume")
            if not df_flows.empty:
                chart = alt.Chart(df_flows).mark_line().encode(
                    x='Timestamp',
                    y='Bytes',
                    color='App'
                )
                st.altair_chart(chart, use_container_width=True)
    
    time.sleep(2)