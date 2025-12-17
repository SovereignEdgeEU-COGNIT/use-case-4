def get_authentication_failures(log_content, rules):
    """Analyze log content for authentication failures using rules and generate block events."""
    import re
    import datetime
    import numpy as np

    def extract_logs(log_content):
        timestamps, messages, users, ip_addresses = [], [], [], []
        for line in log_content:
            match = re.match(r"(\w+ \d+ \d+:\d+:\d+)", line)
            if match:
                timestamps.append(match.group(1))
                messages.append(line.strip())
                user_match = re.search(r"user (\w+)|for (\w+) from", line)
                user = user_match.group(1) if user_match and user_match.group(1) else \
                       user_match.group(2) if user_match and user_match.group(2) else "UNKNOWN"
                users.append(user)
                ip_match = re.search(r"rhost=(\d+\.\d+\.\d+\.\d+)|from (\d+\.\d+\.\d+\.\d+)", line)
                ip = ip_match.group(1) if ip_match and ip_match.group(1) else \
                     ip_match.group(2) if ip_match and ip_match.group(2) else "UNKNOWN"
                ip_addresses.append(ip)
        return timestamps, messages, users, ip_addresses

    def convert_to_unix(timestamps):
        current_year = datetime.datetime.now().year
        unix_times = []
        hours = []
        for time in timestamps:
            dt = datetime.datetime.strptime(f"{current_year} {time}", "%Y %b %d %H:%M:%S")
            unix_times.append(dt.timestamp())
            hours.append(dt.hour)
        return np.array(unix_times).reshape(-1, 1), hours

    def determine_severity(hour, user, ip_address, message):
        reason = None
        if re.search(r"logged out", message, re.IGNORECASE):
            return 0, reason
        if re.search(r"sudo: ", message, re.IGNORECASE) and not re.search(r"user NOT in sudoers", message, re.IGNORECASE):
            reason = "Perhaps a privilege escalation attempts"
            return 0, reason
        if re.search(r"Invalid user|multiple authentication failures|user NOT in sudoers", message, re.IGNORECASE):
            if re.search(r"Invalid user", message, re.IGNORECASE):
                reason = "Failed authentication attempts (Invalid user)"
            elif re.search(r"multiple authentication failures", message, re.IGNORECASE):
                reason = "Failed authentication attempts (repeated failures)"
            else:
                reason = "Privilege escalation attempts"
            return 3, reason
        if re.search(r"pam_unix\(sshd:auth\): authentication failure|Failed password for", message, re.IGNORECASE):
            user_exists = any(u.get('user') == user for u in rules.get('users', []))
            if not user_exists:
                return 3, "Failed authentication attempts (Invalid user)"
            if re.search(r"Failed password for", message, re.IGNORECASE):
                reason = "Failed authentication attempts (repeated failures)"
                return 3, reason
        for user_rule in rules.get('users', []):
            if user == user_rule.get('user'):
                time_ranges = user_rule.get('time_ranges', [])
                for time_range in time_ranges:
                    if hour < time_range.get('start_hour', 0) or hour > time_range.get('end_hour', 24):
                        reason = "Unusual access patterns or times"
                        return 2, reason
        if ip_address not in rules.get('ips', []):
            reason = "Network anomalies - unusua IP"
            return 1, reason
        return 0, reason

    try:
        if not log_content:
            return {
                "message": "No logs to analyze",
                "anomalies": [],
            }

        timestamps, messages, users, ip_addresses = extract_logs(log_content)
        if not timestamps:
            return {
                "message": "No logs to analyze",
                "anomalies": [],
            }

        _, hours = convert_to_unix(timestamps)

        confirmed_anomalies = []

        for i, timestamp in enumerate(timestamps):
            severity, reason = determine_severity(hours[i], users[i], ip_addresses[i], messages[i])
            if severity > 0:
                confirmed_anomalies.append({
                    "log_entry": messages[i],
                    "user": users[i] if users[i] != "UNKNOWN" else None,
                    "ip_address": ip_addresses[i] if ip_addresses[i] != "UNKNOWN" else None,
                    "timestamp": timestamp,
                    "severity": severity,
                    "reason": reason or "no specific reason",
                })
        if confirmed_anomalies:
            result_message = f"Detected {len(confirmed_anomalies)} confirmed anomalies"

        else:
            result_message = "No confirmed anomalies found"
        return {
            "message": result_message,
            "anomalies": confirmed_anomalies,
        }

    except Exception as e:
        return {
            "message": f"An error occurred while analyzing the log file: {str(e)}",
            "anomalies": [],
            "error": str(e)
        }
