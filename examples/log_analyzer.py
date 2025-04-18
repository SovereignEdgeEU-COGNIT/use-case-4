"""This module contains functions for analyzing log files and generating security events."""

def get_authentication_failures(log_content, rules):
    """Analyze log content for authentication failures using decision tree and generate block events.
    
    Args:
        log_content: List of log lines to analyze
        rules: Rules configuration for validation
        
    Returns:
        Dictionary containing detected anomalies and recommended events
    """
    import re
    import datetime
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import StandardScaler

    def extract_logs(log_content):
        """Extract logs from a list of lines"""
        timestamps, messages, event_types, users, ip_addresses = [], [], [], [], []
        for line in log_content:
            match = re.match(r"(\w+ \d+ \d+:\d+:\d+)", line)
            if match:
                timestamps.append(match.group(1))
                messages.append(line.strip())
                event_type = re.search(r"(\bCRON\b|\bsshd\b|\bsystemd\b)", line)
                event_types.append(event_type.group(1) if event_type else "UNKNOWN")
                user_match = re.search(r"user (\w+)|for (\w+) from", line)
                user = user_match.group(1) if user_match and user_match.group(1) else \
                       user_match.group(2) if user_match and user_match.group(2) else "UNKNOWN"
                users.append(user)
                ip_match = re.search(r"rhost=(\d+\.\d+\.\d+\.\d+)|from (\d+\.\d+\.\d+\.\d+)", line)
                ip = ip_match.group(1) if ip_match and ip_match.group(1) else \
                     ip_match.group(2) if ip_match and ip_match.group(2) else "UNKNOWN"
                ip_addresses.append(ip)
        return timestamps, messages, event_types, users, ip_addresses

    def convert_to_unix(timestamps):
        """Convert timestamps to Unix timestamps"""
        current_year = datetime.datetime.now().year
        unix_times = []
        hours = []
        dt_objects = []
        for time in timestamps:
            dt = datetime.datetime.strptime(f"{current_year} {time}", "%Y %b %d %H:%M:%S")
            unix_times.append(dt.timestamp())
            hours.append(dt.hour)
            dt_objects.append(dt)
        return np.array(unix_times).reshape(-1, 1), hours, dt_objects

    def determine_severity(hour, user, ip_address, message):
        """
        Determine the severity level of a potential security anomaly.
        
        Args:
            hour: Hour of the day when the event occurred
            user: Username involved in the event
            ip_address: IP address from which the event originated
            message: Full log message

        Returns:
            int: Severity level
            0: Not an anomaly (normal behavior)
            1: IP-based anomaly (valid user from unknown IP)
            2: Time-based or credentials-based anomaly (valid user at invalid time, login failures)
            3: Highly suspicious activity (unknown user, multiple failures, etc.)
        """
        # Check for known normal patterns first
        if re.search(r"logged out", message, re.IGNORECASE):
            return 0

        # Skip normal sudo events, but flag sudo failures
        if re.search(r"sudo: ", message, re.IGNORECASE) and not re.search(r"user NOT in sudoers", message, re.IGNORECASE):
            return 0

        # Check for highly suspicious activity (severity 3)
        if re.search(r"Invalid user|multiple authentication failures|user NOT in sudoers", message, re.IGNORECASE):
            return 3
            
        # Check for authentication failures (severity 3)
        if re.search(r"pam_unix\(sshd:auth\): authentication failure|Failed password for", message, re.IGNORECASE):
            # Check if user exists in the rules
            user_exists = any(u.get('user') == user for u in rules.get('users', []))
            if not user_exists:
                # Unknown user attempting to log in - highly suspicious
                return 3

        # Check for time-based violations (severity 2)
        for user_rule in rules.get('users', []):
            if user == user_rule.get('user'):
                # Check if this user has time range restrictions
                time_ranges = user_rule.get('time_ranges', [])
                
                if time_ranges:
                    # Check if login attempt is outside allowed hours
                    for time_range in time_ranges:
                        if hour < time_range.get('start_hour', 0) or hour > time_range.get('end_hour', 24):
                            return 2

        # Check for IP-based anomalies (severity 1)
        if ip_address not in rules.get('ips', []):
            return 1

        # If we reach here, no anomaly was detected
        return 0
    
    try:
        # Handle empty log content
        if not log_content:
            return {
                "message": "No logs to analyze",
                "anomalies": [],
                "events": []
            }

        timestamps, messages, event_types, users, ip_addresses = extract_logs(log_content)

        # If no logs were extracted, return early
        if not timestamps:
            return {
                "message": "No logs to analyze",
                "anomalies": [],
                "events": []
            }
            
        unix_times, hours, dt_objects = convert_to_unix(timestamps)

        # Prepare feature extraction for messages
        vectorizer = TfidfVectorizer(max_features=100, min_df=2)
        message_features = vectorizer.fit_transform(messages).toarray()

        event_types_encoded = pd.factorize(pd.Series(event_types))[0].reshape(-1, 1)
        users_encoded = pd.factorize(pd.Series(users))[0].reshape(-1, 1)
        ip_encoded = pd.factorize(pd.Series(ip_addresses))[0].reshape(-1, 1)

        features = np.hstack((unix_times, message_features, event_types_encoded, users_encoded, ip_encoded))

        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)

        model = IsolationForest(contamination=0.01, max_samples='auto', random_state=42, n_jobs=-1, n_estimators=100, warm_start=True)
        model.fit(features_scaled)

        anomalies = model.predict(features_scaled)

        results = []
        confirmed_anomalies = []
        events = []
        
        for i, timestamp in enumerate(timestamps):
            if anomalies[i] == -1:  # Detected as an anomaly by the model
                severity = determine_severity(hours[i], users[i], ip_addresses[i], messages[i])

                if severity > 0:  # If it's a confirmed anomaly with severity
                    results.append(f"{timestamp} - {messages[i]} (confirmed anomaly, severity {severity})")
        
                    # Get user and IP (if available)
                    user = users[i] if users[i] != "UNKNOWN" else None
                    ip = ip_addresses[i] if ip_addresses[i] != "UNKNOWN" else None

                    # Skip if no user identified
                    if not user:
                        continue
                    
                    # Create structured anomaly record
                    confirmed_anomalies.append({
                        "log_entry": messages[i],
                        "user": user,
                        "ip_address": ip,
                        "timestamp": timestamp,
                        "severity": severity
                    })
                    
                    # Generate "event"
                    event = {
                        "user": user,
                        "severity": severity,
                        "ip": ip,
                        "timestamp": dt_objects[i].isoformat(),
                        "reason": "Anomalous login activity detected"
                    }
                    
                    # Add IP for targeted blocking if available and severity is 1 (IP-specific)
                    if ip and ip != "UNKNOWN" and severity == 1:
                        event["ip"] = ip
                        
                    events.append(event)

        # Prepare result message
        if confirmed_anomalies:
            result_message = f"Detected {len(confirmed_anomalies)} confirmed anomalies"
        else:
            result_message = "No confirmed anomalies found"
        
        return {
            "message": result_message,
            "anomalies": confirmed_anomalies,
            "events": events
        }

    except Exception as e:
        return {
            "message": f"An error occurred while analyzing the log file: {str(e)}",
            "anomalies": [],
            "events": [],
            "error": str(e)
        }
