# SSH Authentication Anomaly Detection

Device client implementation for the Cognit framework that monitors SSH authentication logs, detects suspicious activities, and takes automated security actions.

## Quick Start

Run the device client:

```bash
cd ./examples
python3 uc4_offload_ad_function.py
# or
python3 uc4_offload_cc_function.py
```

### Docker Deployment

```bash
cd ./examples
docker compose build
docker compose up
```

**Note:** Ensure `cognit-template.yml` is properly configured.

## Architecture

- **Device Client** (`uc4_offload_ad_function.py` / `uc4_offload_cc_function.py`): Monitors `auth.log` and executes the offloaded anomaly detection function
- **Anomaly Detection** (`decisionTree.py`): Uses Isolation Forest algorithm with rule-based validation
- **Response Daemon**: Processes detection events and implements SSH blocking actions

## Configuration

### Dependencies

```toml
numpy = "^2.2.3"
pandas = "^2.2.3"
scikit-learn = "^1.6.1"
```

Add to the VM image flavor for the Cognit framework.

### Rules (`rules.yml`)

Defines allowed users, time ranges, and IP addresses:

```yml
users:
  - user: user1
    time_ranges:
      - start_hour: 9
        end_hour: 17
ips:
  - 127.0.0.1
  - 10.8.1.14
```

## Testing

Use the interactive log entry generator:

```bash
python log_entry_and_config_updater.py --log_file ./tmp/auth.log
```

Options:
1. Select predefined entries
2. Generate login outside allowed time range
3. Generate login from invalid IP
4. Custom log entry
5. Update requirements

Monitor Response Daemon:
```bash
journalctl -u response-daemon -f
```

## Additional Examples

- **minimal_offload_sync.py**: Basic Cognit library usage demonstrating requirement uploads and function execution
- **technical-documentation.md**: Detailed architecture and workflow documentation
