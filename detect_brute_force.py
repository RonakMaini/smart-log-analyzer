import pandas as pd


df = pd.read_csv("parsed_logs.csv")  


failed_logins = df[df['event'].str.contains("authentication failure", case=False, na=False)]


failed_by_ip = failed_logins['ip'].value_counts().reset_index()
failed_by_ip.columns = ['ip', 'failed_attempts']


brute_force_ips = failed_by_ip[failed_by_ip['failed_attempts'] >= 10]


print("Total failed login attempts:", len(failed_logins))
print("Total brute-force IPs (>=10 attempts):", len(brute_force_ips))
print("\nTop brute-force IPs:")
print(brute_force_ips.sort_values(by="failed_attempts", ascending=False))


brute_force_ips.to_csv("brute_force_detected.csv", index=False)
