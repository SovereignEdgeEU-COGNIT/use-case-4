"""Add a new log entry to a given log file."""

import random
import argparse
from datetime import datetime

import yaml
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit import PromptSession
from typing import Dict, Tuple
from dataclasses import dataclass
from pathlib import Path

REQUIREMENTS_FILE_PATH = "./faas_requirements.yml"

DUMMY = "\n".join([
    "Feb 24 07:32:39 lt-jla-2024 systemd-logind[941]: Removed session c1." + "\n" +
    "Feb 24 07:32:40 lt-jla-2024 PackageKit: uid 1000 is trying to obtain org.freedesktop.packagekit.system-sources-refresh auth (only_trusted:0)" + "\n" +
    "Feb 24 08:30:01 lt-jla-2024 CRON[24249]: pam_unix(cron:session): session closed for user root" + "\n" +
    "Feb 24 08:31:29 lt-jla-2024 gdm-password]: gkr-pam: unlocked login keyring" + "\n"
])

def log(file, line):
    """Adds a line to the end of the specified file."""
    with open(file, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def generate_timestamp(hour=None):
    """Generates a current timestamp, optionally setting the hour."""
    now = datetime.now()
    if hour is not None:
        now = now.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)
    return now.strftime("%b %d %H:%M:%S")

def load_log_entries(yaml_file):
    """Loads log entries from a YAML file."""
    with open(yaml_file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def format_log_entry(timestamp, entry_type, user, ip_address):
    """Formats a log entry to conform to the expected format."""
    if entry_type == "abnormal":
        message = f"sshd[{random.randint(10000, 99999)}]: Failed password for {user} from {ip_address} port {random.randint(10000, 99999)} ssh2"
    else:
        message = f"sshd[{random.randint(10000, 99999)}]: Accepted password for {user} from {ip_address} port {random.randint(10000, 99999)} ssh2"
    return f"{timestamp} {message}"

def get_user_outside_time_range(rules) -> Tuple[str, int]:
    """Returns a random user and a time outside their allowed time range."""
    # All users should have time ranges at this point due to validation
    # Select a random user
    selected_user = random.choice(rules.get('users', []))
    username = selected_user.get('user')
    
    # Get their time ranges
    time_ranges = selected_user.get('time_ranges', [])
    
    # Find a time outside their allowed ranges
    allowed_hours = set()
    for time_range in time_ranges:
        start = time_range.get('start_hour', 0)
        end = time_range.get('end_hour', 24)
        for hour in range(start, end + 1):
            allowed_hours.add(hour % 24)
    
    # All hours that are not in allowed_hours
    disallowed_hours = [hour for hour in range(24) if hour not in allowed_hours]
    
    if not disallowed_hours:
        # If all hours are allowed (0-24), the user can connect anytime
        # This would be a misconfiguration, but we'll handle it gracefully
        print(f"Warning: User {username} has access during all hours (0-24).")
        print("Generating a random hour as an example...")
        return username, random.randint(0, 23)
    
    return username, random.choice(disallowed_hours)

def get_user_with_invalid_ip(rules) -> Tuple[str, str]:
    """Returns a random user and an IP not in the allowed list."""
    if not rules.get('users'):
        return "unknown_user", "192.168.1." + str(random.randint(2, 254))
    
    # Select a random user
    selected_user = random.choice(rules.get('users', []))
    username = selected_user.get('user')
    
    # Generate an IP not in the allowed list
    valid_ips = rules.get('ips', [])
    # Generate a random IP in 192.168.1.x range that's not in valid_ips
    invalid_ip = None
    while True:
        candidate_ip = "192.168.1." + str(random.randint(2, 254))
        if candidate_ip not in valid_ips:
            invalid_ip = candidate_ip
            break
            
    return username, invalid_ip

@dataclass
class AnomalyDetectionFormData:
    """Store form data persistently"""
    user: str = ""
    ip_address: str = ""
    hour: int = 0
    entry_type: str = ""

class AnomalyDetectionForm:
    """Handle form input with persistence and validation"""
    def __init__(self, rules: Dict):
        self.user_completer = WordCompleter(
            [user_rule.get('user') for user_rule in rules.get('users', [])],
            ignore_case=True
        )
        self.ip_completer = WordCompleter(
            rules.get('ips', []),
            ignore_case=True
        )
        self.data = AnomalyDetectionFormData()

        # Create custom key bindings
        self.kb = KeyBindings()

        @self.kb.add('escape')
        def _(event):
            event.app.exit(exception=KeyboardInterrupt)

        self.session = PromptSession(">> ", key_bindings=self.kb)

    def get_user_input(self, field_name: str, completer=None) -> str:
        """Get validated user input with completion"""
        while True:
            try:
                value = self.session.prompt(
                    f"Enter {field_name}: ",
                    completer=completer,
                    default=str(getattr(self.data, field_name))
                ).strip()
                
                if not value:
                    print(f"{field_name.capitalize()} cannot be empty")
                    continue
                    
                setattr(self.data, field_name, value)
                return value
            except KeyboardInterrupt:
                print("\nOperation cancelled")
                return None

    def collect_form_data(self) -> AnomalyDetectionFormData:
        """Collect all form fields"""
        user = self.get_user_input("user", self.user_completer)
        if user is None:
            return None

        ip_address = self.get_user_input("ip_address", self.ip_completer)
        if ip_address is None:
            return None

        while True:
            try:
                hour_input = self.get_user_input("hour")
                if hour_input is None:
                    return None

                hour = int(hour_input)
                if 0 <= hour <= 23:
                    self.data.hour = hour
                    break
                print("Hour must be between 0 and 23")
            except ValueError:
                print("Please enter a valid hour")
        return self.data

def display_log_entries(log_entries, entry_type):
    """Display all available log entries of a specific type."""
    if entry_type not in log_entries:
        print(f"No {entry_type} entries found")
        return None
        
    entries = log_entries[entry_type]
    print(f"\nAvailable {entry_type} entries:")
    for i, entry in enumerate(entries):
        print(f"{i+1}. {entry}")
    
    while True:
        try:
            selection = input(f"\nSelect an entry (1-{len(entries)}) or 0 to cancel: ")
            if selection == "0":
                return None
                
            idx = int(selection) - 1
            if 0 <= idx < len(entries):
                return entries[idx]
            print(f"Please enter a number between 1 and {len(entries)}")
        except ValueError:
            print("Please enter a valid number")

@dataclass
class RequirementsFormData:
    """Store requirements form data persistently"""
    flavour: str = ""
    min_energy_renewable_usage: int = 85
    max_latency: int = 45

class RequirementsForm:
    """Handle requirements form input with persistence and validation"""
    def __init__(self, config_manager: 'YAMLConfigManager'):
        self.config_manager = config_manager
        self.data = RequirementsFormData()

        # Create custom key bindings
        self.kb = KeyBindings()

        @self.kb.add('escape')
        def _(event):
            event.app.exit(exception=KeyboardInterrupt)

        self.session = PromptSession(">> ", key_bindings=self.kb)

    def get_user_input(self, field_name: str, default_value: str) -> str:
        """Get user input with a default value"""
        try:
            value = self.session.prompt(
                f"{field_name} [{default_value}]: ",
                default=default_value
            ).strip()            
            return value if value else default_value
        except KeyboardInterrupt:
            print("\nOperation cancelled")
            return None

    def collect_form_data(self) -> RequirementsFormData:
        """Collect all form fields"""
        current_config = self.config_manager.load_requirements()

        flavour = self.get_user_input("FLAVOUR", current_config.get('FLAVOUR', 'CybersecV2test1'))
        if flavour is None:
            return None
        self.data.flavour = flavour

        min_energy_renewable_usage = self.get_user_input("MIN_ENERGY_RENEWABLE_USAGE", str(current_config.get('MIN_ENERGY_RENEWABLE_USAGE', 85)))
        if min_energy_renewable_usage is None:
            return None
        try:
            self.data.min_energy_renewable_usage = int(min_energy_renewable_usage)
        except ValueError:
            print("Invalid number format for MIN_ENERGY_RENEWABLE_USAGE. Using default value.")
            self.data.min_energy_renewable_usage = 85

        max_latency = self.get_user_input("MAX_LATENCY", str(current_config.get('MAX_LATENCY', 45)))
        if max_latency is None:
            return None
        try:
            self.data.max_latency = int(max_latency)
        except ValueError:
            print("Invalid number format for MAX_LATENCY. Using default value.")
            self.data.max_latency = 45

        return self.data

class YAMLConfigManager:
    """Manage YAML requirements files"""
    def __init__(self):
        self.config_path = Path(REQUIREMENTS_FILE_PATH)

    def load_requirements(self) -> Dict:
        """Load requirements from YAML file"""
        if not self.config_path.exists():
            return {}
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def save_requirements(self, config: Dict) -> None:
        """Save requirements to YAML file"""
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, indent=4)

    def update_requirements(self, updates: Dict) -> None:
        """Update existing requirements"""
        current_config = self.load_requirements()
        updated_config = {**current_config, **updates}
        self.save_requirements(updated_config)

def confirm_log_entry(entry):
    """Ask the user to confirm adding a log entry."""
    # Extract the actual log entry (remove the DUMMY part)
    actual_entry = entry.split(DUMMY)[-1] if DUMMY in entry else entry
    
    print("\nLog entry to be added:")
    print(actual_entry)
    while True:
        response = input("\nAdd this entry? (y/n): ").lower()
        if response in ('y', 'yes'):
            return True
        if response in ('n', 'no'):
            return False
        print("Please enter 'y' or 'n'")

def validate_user_time_ranges(rules):
    """Validate that all users have time ranges defined.
    
    Args:
        rules: The rules configuration
        
    Returns:
        True if all users have time ranges, False otherwise
    """
    missing_time_ranges = []
    for user_rule in rules.get('users', []):
        user = user_rule.get('user')
        if 'time_ranges' not in user_rule or not user_rule['time_ranges']:
            missing_time_ranges.append(user)
    
    if missing_time_ranges:
        print(f"ERROR: The following users are missing time ranges: {', '.join(missing_time_ranges)}")
        print("Time ranges are mandatory for all users.")
        return False
    return True

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Log entry generator with form handling")
    parser.add_argument("--log_file", default="./auth.log", help="Path to log file")
    parser.add_argument("--yaml_file", default="./log_entries.yml", 
                       help="Path to YAML file with log entries")
    parser.add_argument("--rules_file", default="./rules.yml",
                       help="Path to YAML file with rules")
    parser.add_argument("--config_file", default=REQUIREMENTS_FILE_PATH,
                       help="Path to requirements file")
    
    args = parser.parse_args()

    # Initialize managers
    config_manager = YAMLConfigManager()
    log_entries = load_log_entries(args.yaml_file)
    rules = load_log_entries(args.rules_file)
    
    # Validate that all users have time ranges
    if not validate_user_time_ranges(rules):
        print("Exiting due to missing time ranges.")
        return
    
    form_handler = AnomalyDetectionForm(rules)
    requirements_form = RequirementsForm(config_manager)

    while True:
        print("\n=== Log Entry Generator ===")
        print("1. Select entry from log_entries.yml")
        #print("2. Generate entry: User login outside allowed time range")
        #print("3. Generate entry: User login from invalid IP")
        #print("4. Custom log entry (manual input)")
        print("5. Update requirements")
        print("0. Exit")

        choice = input("Enter your choice (0-5): ")

        if choice == "0":
            print("Exiting.")
            break

        elif choice == "1":
            # List and select from available entries
            print("\nSelect entry type:")
            print("1. Normal entries")
            print("2. Abnormal entries")
            entry_type_choice = input("Enter choice (1-2): ")
            
            if entry_type_choice == "1":
                selected_entry = display_log_entries(log_entries, "normal")
            elif entry_type_choice == "2":
                selected_entry = display_log_entries(log_entries, "abnormal")
            else:
                print("Invalid choice.")
                continue
                
            if selected_entry:
                line_to_add = f"{selected_entry}"
                if confirm_log_entry(line_to_add):
                    log(args.log_file, line_to_add)
                    print(f"Entry added to {args.log_file}.")
            
        elif choice == "2":
            # Generate time-based anomaly
            user, hour = get_user_outside_time_range(rules)
            timestamp = generate_timestamp(hour)
            ip_address = random.choice(rules.get('ips', ['127.0.0.1']))
            line_to_add = DUMMY + format_log_entry(timestamp, "normal", user, ip_address)
            
            print("\nGenerated entry: User login outside allowed time range")
            if confirm_log_entry(line_to_add):
                log(args.log_file, line_to_add)
                print(f"Entry added to {args.log_file}.")
            
        elif choice == "3":
            # Generate IP-based anomaly
            user, invalid_ip = get_user_with_invalid_ip(rules)
            timestamp = generate_timestamp()
            line_to_add = DUMMY + format_log_entry(timestamp, "normal", user, invalid_ip)
            
            print("\nGenerated entry: User login from invalid IP")
            if confirm_log_entry(line_to_add):
                log(args.log_file, line_to_add)
                print(f"Entry added to {args.log_file}.")
            
        elif choice == "4":
            # Interactive form flow - custom log entry
            print("\nSelect entry type:")
            print("1. Normal login")
            print("2. Failed login attempt")
            entry_type_choice = input("Enter choice (1-2): ")
            
            if entry_type_choice not in ["1", "2"]:
                print("Invalid choice.")
                continue
                
            entry_type = "normal" if entry_type_choice == "1" else "abnormal"
            data = form_handler.collect_form_data()
            if data is None:
                continue
            
            timestamp = generate_timestamp(data.hour)
            line_to_add = DUMMY + format_log_entry(
                timestamp,
                entry_type,
                data.user,
                data.ip_address
            )
            
            if confirm_log_entry(line_to_add):
                log(args.log_file, line_to_add)
                print(f"Entry added to {args.log_file}.")
            
        elif choice == "5":
            # Configuration update flow
            data = requirements_form.collect_form_data()
            if data is None:
                continue

            updates = {
                'FLAVOUR': data.flavour,
                'MIN_ENERGY_RENEWABLE_USAGE': data.min_energy_renewable_usage,
                'MAX_LATENCY': data.max_latency
            }

            config_manager.update_requirements(updates)
            print("Requirements updated successfully!")
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()