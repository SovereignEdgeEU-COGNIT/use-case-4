# Anomaly Detection Function

This folder contains the device client function (`uc4_example.py`) that is going to observe the `auth.log` file for changes. Every time new entries enter the log file it exectutes the offloaded anomaly detection function, named `get_authentication_failures` in the `log_analyzer.py` file.

### Running the use case script

To execute the script, navigate to the examples directory and run the following command:

```bash
cd ./examples
python3 uc4_example.py
```

#### Dependencies

Some dependencies are required

```toml
numpy = "^2.2.3"
pandas = "^2.2.3"
scikit-learn = "^1.6.1"
```

**Note**: They should be added to the flavor image when creating the VM image for the Cognit framework.

## Run example with Docker

This example can also be executed within Docker. A Dockerfile named `minimal_offload_sync.dockerfile` is provided to build the image along with a Docker Compose file to help run it.

### Steps to run with Docker

1. **Install Docker**

    Follow the official Docker installation instructions: [Docker Installation Guide](https://docs.docker.com/get-docker/)

2. **Deploy Docker stack**

    To build and run the image, make sure you are located in the examples directory. Then type the following commands:

    ```bash
    cd ./examples
    docker compose build
    docker compose up
    ```

> **Important**  
> Make sure the configuration file `cognit-template.yml` has the correct parameters.

## Rules for the anomaly detection

The `uc4_example.py` example uses a YAML file (see `examples/rules.yml`) containing rules to check for valid events.

Here is an example of the file structure

```yml
users:
  - user: user1
    time_ranges:
      - start_hour: 9
        end_hour: 17
  - user: user2
    time_ranges:
      - start_hour: 0
        end_hour: 24
ips:
  - 127.0.0.1
  - 10.8.1.14
  - 10.11.250.251
```

The above rules say

- only `user1` and `user2` may connect
- `user1`'s events can only occur between 9AM and 5PM
- `user2`'s events can occur at any time
- user can only connect from the given IP addresses

## How to test the example?

To test the `uc4_example.py` you can use the `examples/log_entry_and_config_updater.py` script.

The script is a CLI application that enables to interactively update the `auth.log` file that is used by the offloaded anomaly detection function.

When started you get the following text-based user interfaces (TUI)

```
=== Log Entry Generator ===

1. Select entry from log_entries.yml
2. Generate entry: User login outside allowed time range
3. Generate entry: User login from invalid IP
4. Custom log entry (manual input)
5. Update requirements
0. Exit

Enter your choice (0-5):
```

When you select to add some entries the tool shows the entry that is going to be added and asks for confirmation

```
Log entry to be added:
Apr 01 02:46:24 sshd[96161]: Accepted password for user2 from 10.11.250.251 port 82668 ssh2

Add this entry? (y/n): y
```

## Minimal example

The file [minimal_offload_sync](minimal_offload_sync.py) demonstrates the basic usage of the COGNIT library. In this example, you’ll learn how to upload requirements to the COGNIT environment and execute functions within it.

The [technical-documentation.md](technical-documentation.md) file provides the technical documentation of the example.

### Uploading requirements

Requirements can be uploaded in two ways:

1. Using the `init()` function with a JSON object:

    ```python
    my_device_runtime.init(TEST_REQS_INIT)
    ```

2. Using the `call()` function, with an optional parameter new_reqs to update the requirements on-the-fly:

    ```python
    my_device_runtime.call(multiply, 2, 3, new_reqs=TEST_REQS_INIT)
    ```

This example also shows that requirements can be updated dynamically whenever needed.
