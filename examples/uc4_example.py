"""Example for UC4."""
import sys
sys.path.append(".")

import time
import json
from pathlib import Path
import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from cognit import device_runtime
from cognit.models._edge_cluster_frontend_client import ExecReturnCode

from log_analyzer import get_authentication_failures

LOG_FILE_PATH = "/cognit/examples/auth.log"
DEVICE_RUNTIME_CONFIG_PATH = "/cognit/examples/cognit-template.yml"
REQUIREMENTS_FILE_PATH = "/cognit/examples/faas_requirements.yml"
RULES_FILE_PATH = "/cognit/examples/rules.yml"
QUEUE_FILE_PATH = "/cognit/queue/queue.json"

def load_requirements(requirements_path: str) -> dict:
    """Load requirements from YAML file.
    
    Args:
        requirements_path: Path to the YAML requirements file
        
    Returns:
        Dictionary containing the requirements
        
    Raises:
        FileNotFoundError: If the requirements file doesn't exist
        yaml.YAMLError: If the requirements file is invalid
    """
    with open(requirements_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

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

class LogHandler(FileSystemEventHandler):
    """Handler for auth.log file changes."""

    def __init__(self, log_path: str, dr: device_runtime.DeviceRuntime, rules: dict, queue_path: str):
        """Initialize the handler with the log path, device runtime and queue path.

        Args:
            log_path: Path to the auth.log file
            device_runtime: Initialized DeviceRuntime instance
            rules: Rules for validation
            queue_path: Path to the queue file for blocking requests
        """
        self.log_path = f"{Path(log_path)}"
        self.device_runtime = dr
        self.last_position = Path(log_path).stat().st_size if Path(log_path).exists() else 0
        self.rules = rules
        self.requirements = None
        self.queue_path = queue_path

    def change_requirements(self, requirements: dict):
        """Change the requirements file path.

        Args:
            requirements: New path set of requirements to apply
        """
        self.requirements = requirements

    def process_events(self, result: dict) -> int:
        """Process and add events to the queue file.
        
        Args:
            result: Result dictionary from the log analysis function
            
        Returns:
            Number of events added to the queue
        """
        events = result.get('events', [])
        if not events:
            return 0
            
        # Create the queue file and directory if they don't exist
        queue_file = Path(self.queue_path)
        queue_file.parent.mkdir(parents=True, exist_ok=True)
        
        if not queue_file.exists():
            queue_file.touch()
            
        events_count = 0
        
        for event in events:
            # Create a unique key to identify this event
            user = event.get('user')
            ip = event.get('ip', 'global')
                
            # Add the event to the queue
            try:
                with open(queue_file, "a") as f:
                    f.write(json.dumps(event) + "\n")
                
                print(f"Added severity {event['severity']} event for user {user}" +
                      (f" from IP {ip}" if ip != 'global' else "") +
                      f" for {event.get('block_minutes_duration', 'N/A')} minutes to {self.queue_path}")
                
                events_count += 1
                
            except (OSError, IOError, json.JSONDecodeError) as e:
                print(f"Error adding event to queue: {e}")
        
        return events_count

    def on_modified(self, event):
        """Handle file modification events."""

        if self.requirements is not None:
            print(f"Initializing device runtime with new requirements: {self.requirements}")

            self.device_runtime.init(self.requirements)
            self.requirements = None

        if event.src_path == self.log_path:
            print(f"File {event.src_path} has been modified")
            # Read only new lines
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    f.seek(self.last_position)
                    new_lines = f.readlines()

                    if new_lines:
                        # Process new lines through the COGNIT runtime
                        status_code, result = self.device_runtime.call(
                            get_authentication_failures, new_lines, self.rules
                        )

                        if status_code == ExecReturnCode.SUCCESS:
                            self.last_position = f.tell()
                            print(f"Processed new log entries. Results: {str(result)}", flush=True)
                                
                            # Process events and add them to the queue
                            count = self.process_events(result)
                            
                            if count > 0:
                                print(f"Added {count} events to the queue")
                            elif 'message' in result:
                                print(f"Analysis result: {result['message']}")

                        else:
                            print(f"Error processing log entries: {str(result)}", flush=True)
            except FileNotFoundError:
                print(f"Log file {self.log_path} not found, waiting for it to be created")

class RequirementsHandler(FileSystemEventHandler):
    """Handler for requirements file changes."""

    def __init__(self, requirements_path: str, log_handler: LogHandler):
        """Initialize the handler with the file path and log file handler.

        Args:
            requirements_path: Path to the requirements file
            logHandler: LogHandler instance
        """
        self.requirements_path = f"{Path(requirements_path)}"
        self.log_handler = log_handler

    def on_modified(self, event):
        """Handle file modification events."""

        print(f"File {event.src_path} has been modified")
        print(f"Reloading requirements from {self.requirements_path}")
        if event.src_path == self.requirements_path:
            print(f"File {event.src_path} has been modified")

            self.log_handler.change_requirements(load_requirements(self.requirements_path))

def main():
    """Start anomaly detection."""
    try:
        
        print(f"Loading requirements from: {REQUIREMENTS_FILE_PATH}")
        requirements = load_requirements(REQUIREMENTS_FILE_PATH)

        rules = load_requirements(RULES_FILE_PATH)
        if not validate_user_time_ranges(rules):
            print("Exiting due to missing time ranges.")
            return

        # Initialize the device runtime
        dr = device_runtime.DeviceRuntime(DEVICE_RUNTIME_CONFIG_PATH)
        dr.init(requirements)

        # Set up the log file observer
        log_observer = Observer()
        log_handler = LogHandler(LOG_FILE_PATH, dr, rules, QUEUE_FILE_PATH)
        log_observer.schedule(
            log_handler, path=str(Path(LOG_FILE_PATH)), recursive=False
        )
        log_observer.start()

        # Set up the requirements file observer
        requirements_observer = Observer()
        requirements_handler = RequirementsHandler(REQUIREMENTS_FILE_PATH, log_handler)
        requirements_observer.schedule(
            requirements_handler, path=str(Path(REQUIREMENTS_FILE_PATH)), recursive=False
        )
        requirements_observer.start()

        print(f"Started monitoring {LOG_FILE_PATH} and {REQUIREMENTS_FILE_PATH}")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log_observer.stop()
            requirements_observer.stop()
            print("\nStopping log and requirements monitor...")

        log_observer.join()
        requirements_observer.join()

    except FileNotFoundError as e:
        print(f"Configuration file not found: {e}")
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file: {e}")
    # pylint: disable=W0718
    except Exception as e:
        print(f"Error in log monitoring: {e}")

if __name__ == "__main__":
    main()
