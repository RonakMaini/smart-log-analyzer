import streamlit as st
import pandas as pd
import smtplib
from email.message import EmailMessage
import io

# === Email Alert Function (Excel Attachment) ===
def send_email_alert(suspicious_df):
    if suspicious_df.empty:
        st.warning("No suspicious data to send.")
        return

    sender = "priyanshuswami678@gmail.com"  # Replace with your Gmail
    receiver = "ronakmainicode@gmail.com"  # Replace with recipient
    password = "ztna wsyl jmun ioys"

    subject = "🚨 Alert: Suspicious IP Activity Detected"
    body = "Attached is a report of IPs with suspicious login activity."

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = receiver

    # Excel attachment
    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
        suspicious_df.to_excel(writer, index=False, sheet_name='Suspicious IPs')
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
        st.warning(f"Failed to send email: {e}")

# === Streamlit App ===

st.set_page_config(page_title="System Log Threat Dashboard", layout="wide")
st.title("🔐 System Log Threat Dashboard")

# === Load Logs ===
try:
    # Replace with your file path if needed
    df_logs = pd.read_csv("parsed_logs.csv")

    # === Process Failed Logins ===
    failed_logins = df_logs[df_logs['event'].str.contains("authentication failure", case=False, na=False)]
    failed_by_ip = failed_logins['ip'].value_counts().reset_index()
    failed_by_ip.columns = ['IP Address', 'Failed Attempts']

    suspicious_ips_df = failed_by_ip[failed_by_ip['Failed Attempts'] >= 10]

    # Determine username column
    user_col = 'username' if 'username' in df_logs.columns else 'user'

    # Merge with user and timestamp info
    if user_col in df_logs.columns and 'timestamp' in df_logs.columns:
        latest_attempts = (
            failed_logins.groupby('ip')
            .agg({
                user_col: 'last',
                'timestamp': 'last'
            })
            .reset_index()
            .rename(columns={'ip': 'IP Address', user_col: 'Username', 'timestamp': 'Last Attempt'})
        )
        threat_df = pd.merge(failed_by_ip, latest_attempts, on="IP Address", how="left")
        threat_df["Last Attempt"] = threat_df["Last Attempt"].astype(str)
    else:
        threat_df = failed_by_ip.copy()
        threat_df['Username'] = 'Unknown'
        threat_df['Last Attempt'] = 'N/A'

    # === Dashboard UI ===
    total_failed_logins = len(failed_logins)
    total_suspicious_ips = len(suspicious_ips_df)

    col1, col2 = st.columns(2)
    col1.metric("Total Failed Logins", total_failed_logins)
    col2.metric("Suspicious IPs (≥10 Attempts)", total_suspicious_ips)

    st.subheader("📊 Failed Attempts per IP")
    st.bar_chart(threat_df.set_index("IP Address")[["Failed Attempts"]])

    st.subheader("🕵️ Suspicious Activity Details")
    st.dataframe(threat_df)

    # === Email Alert Section ===
    st.subheader("📨 Send Alert Email")
    if st.button("Send Alert Email for Suspicious IPs"):
        send_email_alert(threat_df[threat_df["Failed Attempts"] >= 10])

except FileNotFoundError:
    st.error("❌ 'parsed_logs.csv' not found. Please check the file path.")
except Exception as e:
    st.error(f"❌ An error occurred: {e}")
