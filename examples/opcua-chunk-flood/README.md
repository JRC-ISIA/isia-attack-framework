 # Attack Flood Example for ISIA Testbed
 
 The attack definition ([attack-plan.json](attack-plan.json)) for the coordinator performs the following:

1. Define alias *attack-client01* for node IP 172.17.22.51
1. Execute the start-profiler script which starts detailed logging of the PLCs on 24th March 2026 at 16:00 (CET).
1. Start the network traffic capture directly after sending the previous task command.
1. Wait 10 seconds and then start the first attack script to discover devices with open OPC UA ports on the attacker device (attack-client01).
1. Dump all accessible OPC UA nodes 10 seconds after the previous task has finished (task ID 4 is set to blocking).
1. Identify injection moulding machines based on dumps 10 seconds after the previous task has finished.
1. Perform the OPC UA chunk flood attack 10 seconds after the previous task has finished.
1. Stop network traffic capture 10 seconds after the previous task has finished.
1. Stop detailed logging on PLCs 10 seconds after the previous task has finished.
1. Download PLC logs 1 minute after the previous task has finished.
1. Extract features from logs.
1. Store dataset on network NAS once the feature extraction has finished.