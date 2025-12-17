import sys
import time
sys.path.append(".")

from cognit import device_runtime

# Functions used to be uploaded
def set_secret():
    print("Secret reinitialization")
    new_secret="CETIC_API_KEY=12345azert"
    print(new_secret)
    return "New secret updated [1]"

result = my_device_runtime.call(set_secret)                     # type: ignore

REQS_INIT = {
    "ID": "device-client-002",
    "FLAVOUR": "CyberSecurity",
    "IS_CONFIDENTIAL": True,
    "GEOLOCATION": {
        "latitude": 48.5839,
        "longitude": 7.7458
    }
}

try:

    # Instantiate a device Device Runtime
    my_device_runtime = device_runtime.DeviceRuntime("./examples/cognit-template.yml")
    my_device_runtime.init(REQS_INIT)
    # Synchronous offload and execution of a function
    
    result = my_device_runtime.call(set_secret)

    print("-----------------------------------------------")
    print("Status: " + str(result))
    print("-----------------------------------------------")

    my_device_runtime.stop()

except Exception as e:
    
    print("An exception has occurred: " + str(e))
    exit(-1)