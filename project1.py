import streamlit as st
import pandas as pd
import smtplib
from email.message import EmailMessage
import io

def send_email_alert(full_df):
    if full_df.empty:
        st.warning("No data to send.")
        return

    sender = "priyanshuswami678@gmail.com"
    receiver = "mittalharsh2107@gmail.com"
    password = "ztna wsyl jmun ioys"

    subject = "🚨 Alert: Suspicious IP Activity Detected"
    body = f"{len(full_df)} suspicious IPs detected.\nAttached is the full report."

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = receiver

    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
        full_df.to_excel(writer, index=False, sheet_name='Suspicious IPs')
    excel_buffer.seek(0)

    msg.add_attachment(
        excel_buffer.read(),
        maintype='application',
        subtype='vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        filename='suspicious_ips.xlsx'
    )

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.send_message(msg)
        st.success("📧 Email with Excel attachment sent successfully.")
    except Exception as e:
        st.error(f"❌ Failed to send email: {e}")

st.set_page_config(page_title="System Log Threat Dashboard", layout="wide")
st.title("🔐 System Log Threat Dashboard")

try:
    df_logs = pd.read_csv("parsed_logs.csv")

    failed_logins = df_logs[df_logs['event'].str.contains("authentication failure", case=False, na=False)]
    failed_by_ip = failed_logins['ip'].value_counts().reset_index()
    failed_by_ip.columns = ['IP Address', 'Failed Attempts']

    suspicious_ips_df = failed_by_ip[failed_by_ip['Failed Attempts'] >= 10]

    user_col = 'username' if 'username' in df_logs.columns else 'user'

    if user_col in df_logs.columns and 'timestamp' in df_logs.columns:
        latest_info = (
            failed_logins.groupby('ip')
            .agg({
                user_col: 'last',
                'timestamp': 'last'
            })
            .reset_index()
            .rename(columns={'ip': 'IP Address', user_col: 'Username', 'timestamp': 'Last Attempt'})
        )
        threat_df = pd.merge(failed_by_ip, latest_info, on="IP Address", how="left")
        threat_df["Last Attempt"] = threat_df["Last Attempt"].astype(str)
    else:
        threat_df = failed_by_ip.copy()
        threat_df['Username'] = 'Unknown'
        threat_df['Last Attempt'] = 'N/A'

    st.metric("Total Failed Logins", len(failed_logins))
    st.metric("Suspicious IPs (≥10 Attempts)", len(suspicious_ips_df))

    st.subheader("📊 Failed Attempts per IP")
    st.bar_chart(threat_df.set_index("IP Address")[["Failed Attempts"]])

    st.subheader("🕵️ Suspicious Activity Details")
    st.dataframe(threat_df)

    st.subheader("📨 Send Alert Email")
    if st.button("Send Alert Email with Report"):
        send_email_alert(threat_df)

except FileNotFoundError:
    st.error("❌ 'parsed_logs.csv' not found.")
except Exception as e:
    st.error(f"❌ An error occurred: {e}")
