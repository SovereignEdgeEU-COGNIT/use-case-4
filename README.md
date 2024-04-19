# Use Case 4 - CyberSecurity

![Use Case 4 - CyberSecurity](img/uclogo.png)

UseCase 4 of the project focuses on Cybersecurity and highlights the utility of the COGNIT framework through the implementation of an anomaly detection scenario within a fleet of rovers (vehicles). The current architecture of the scenario includes the following components:
Rover Data Collection: Rovers collect data, including system logs and metrics such as location, speed, and distance between vehicles.
Data Transfer: The collected data is transmitted to the anomaly detection, which is deployed at the cluster level. This step aims to ensure fast (low latency) and secure transmission of data to the detection system.
Anomaly Detection: Anomaly detection is performed using a Serverless Runtime. This component analyses incoming data to identify any significant deviations from normal behaviour patterns.
Migration Management: A crucial aspect of UseCase 4 is to demonstrate the COGNIT framework's ability to manage the migration of serverless runtimes based on the itinerary and movement of the rovers. This functionality ensures service continuity and operational efficiency even in dynamic and constantly evolving environments.

Here is a high level diagram of the architecture :    
![Use Case 4 - CyberSecurity](img/uc_hl_archi.png)

We implemented an architecture represented in the diagram below, which illustrates the interaction of our use case with the framework.


We developed a function named “get_authentication_failures”, intended to be executed within the Serverless Runtime. This function uses a regular expression to search for authentication failures within the content of a log file. If authentication failures are detected, the function returns a warning message indicating the details of suspicious connection attempts. Otherwise, it indicates that everything is normal.

```python
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
       return "An error occurred while analysing the log file:"  + str(e)
```

Next, we demonstrate how to invoke this function via the framework, by retrieving the content of the log file and passing it as a parameter to the function. We used the call_sync method to execute the function synchronously on the Serverless Runtime, providing the function and the log file content as parameters.

```python
# Example offloading a function call to the Serverless Runtime
# Loading the log file
log_file_path = "./examples/auth.log"
Try:
   with open(log_file_path, "r") as log_file:
       log_content = log_file.read()
except FileNotFoundError:
   print("The specified log file does not exist.")
except Exception as e:
   print("An error occurred while reading the log file:", e)

# call_sync sends to execute sync.ly to the already assigned Serverless Runtime.
# First argument is the function, followed by the parameters to execute it.
result = my_cognit_runtime.call_sync(get_authentication_failures, log_content)
print("Offloaded function result:", result)
```
Finally, the result of the successful execution of the function is displayed by the Device Client Runtime, showing that authentication failures have been successfully detected, if any, and that the system is functioning as expected.
```shell
device_client_runtime | COGNIT Serverless Runtime ready!

device_client_runtime | [2024-04-12 12:05:52,171] [WARNING] [_serverless_runtime_client.py::48] Faas execute sync [POST] URL: http://[2001:67c:22b8:1::e]:8000/v1/faas/execute-sync

device_client_runtime | Offloaded function result: ret_code=<ExecReturnCode.SUCCESS: 0> res='Anomaly Detection : Warning ! Connection attempt : 
- Apr 12 09:22:36 cognit-device-runtime sshd[248279]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=X.X.X.X  user=atthacker
- Apr 12 10:22:36 cognit-device-runtime sshd[248279]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=X.X.X.X  user=atthacker' err=None
```