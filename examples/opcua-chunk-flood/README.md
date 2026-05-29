 # Attack Flood Example for ISIA Testbed
 
 The attack definition ([attack-plan.json](attack-plan.json)) defines the following:

1. Define alias for attack-client01
1. Execute the start-profiler script which starts detailed logging of the PLCs
1. Start the network traffic capture
1. Start the first attack script to discover devices with open OPC UA ports on the attacker device (attack-client-01)
1. Dump all accessible OPC UA nodes
1. Identify injection moulding machines based on dumps
1. Perform the OPC UA chunk flood attack 
1. Stop network traffic capture
1. Stop detailed logging on PLCs
1. Download PLC logs
1. Extract features from logs
1. Store dataset on network NAS