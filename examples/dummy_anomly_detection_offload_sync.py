# This is needed to run the example from the cognit source code
# If you installed cognit with pip, you can remove this
import sys
import time

sys.path.append(".")

import time

from cognit import (
    EnergySchedulingPolicy,
    FaaSState,
    ServerlessRuntimeConfig,
    ServerlessRuntimeContext,
)

def get_authentication_failures(log_content):
    import re
    try:
        authentication_failures = []
        for line in log_content.split('\n'):
            if re.search(r'pam_unix\(sshd:auth\): authentication failure', line):
                authentication_failures.append(line.rstrip())  
        if authentication_failures:
            result_message = "Anomaly Detection : Warning ! Connection attempt : \n" + "\n".join(authentication_failures)
        else:
            result_message = "Anomaly Detection : No message, Everything is fine"
        return result_message
    except Exception as e:
        return "An error occurred while analyzing the log file:" + str(e)

# Configure the Serverless Runtime requeriments
sr_conf = ServerlessRuntimeConfig()
sr_conf.name = "Example Serverless Runtime"
sr_conf.scheduling_policies = [EnergySchedulingPolicy(50)]
# This is where the user can define the FLAVOUR to be used within COGNIT to deploy the FaaS node.
sr_conf.faas_flavour = "Cybersec"

# Request the creation of the Serverless Runtime to the COGNIT Provisioning Engine
try:
    # Set the COGNIT Serverless Runtime instance based on 'cognit.yml' config file
    # (Provisioning Engine address and port...)
    my_cognit_runtime = ServerlessRuntimeContext(config_path="./examples/cognit.yml")
    # Perform the request of generating and assigning a Serverless Runtime to this Serverless Runtime context.
    ret = my_cognit_runtime.create(sr_conf)
except Exception as e:
    print("Error in config file content: {}".format(e))
    exit(1)


# Wait until the runtime is ready

# Checks the status of the request of creating the Serverless Runtime, and sleeps 1 sec if still not available.
while my_cognit_runtime.status != FaaSState.RUNNING:
    time.sleep(1)

print("COGNIT Serverless Runtime ready!")

# Example offloading a function call to the Serverless Runtime

# call_sync sends to execute sync.ly to the already assigned Serverless Runtime.
# First argument is the function, followed by the parameters to execute it.

log_file_path = "./examples/auth.log"

try:
    with open(log_file_path, "r") as log_file:
        log_content = log_file.read()
except FileNotFoundError:
    print("The specified log file does not exist.")
except Exception as e:
    print("An error occurred while reading the log file:", e)


time.sleep(45)
result = my_cognit_runtime.call_sync(get_authentication_failures, log_content)
print("Offloaded function result:", result)


# This sends a request to delete this COGNIT context.
my_cognit_runtime.delete()

print("COGNIT Serverless Runtime deleted!")
