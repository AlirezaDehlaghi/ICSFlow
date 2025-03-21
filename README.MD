
# ICSFLowGenerator in Docs

This is tool for offline and online processing of network packets and creating network flows.



## Capabilities
Reading packets could be done in two modes
* offline from PCAP file
* online sniffing of LAN

We can annotate data using True labels or predicted labels
* Ture Labels (approach 1): proving attack history log files, it can detect which flows are malicious 
* Ture Labels (approach 2): proving metadata about packets, it can detect which flows are malicious
* Predicated Labels: We could also try to analyze network flows with pretrained model and predict its anomality. 


## Arguments 
```
positional arguments:  <action:sniff|convert>
                        Choose online sniffing of a LAN or offline converting
                        PCAP file
```
```
options:  
  --source <source file or LAN name>>  
                        In online sniffing provide <LAN name> and in offline  
                        converting provide <PCAP file>  
  --interval <Float> interval in seconds.
                        interval to compute flows.
  --use_port <True or False> indicating the usage of port address.
                        <Determines whether the port number should be included when identifying network.addresses.>
  --attacks_time <string> file address for attack log csv file.
                        attack file address for finding anomalous flows' label.
  --attacks_packet <string> file address for attack packet information csv file.
                        a file address for a CSV file that indicate which packets are anomalous.
  --ids <string> file address for AI model that act as intrusion detection system.
                        address of pre trained ml model to classify incoming flows.
  --target_connection <string> file address for the file indicating details of target connection.
                        Target server connection file to stream out network flows.
  --target_file <string> file address for the output csv file.
                        csv file to output.
```

## Sample runtime arguments
1) sniffing from Wi-Fi lan without annotation and writing flows to file:
```
sniff 
    --source   Wi-Fi   
    --interval   0.5   
    --target_file   output/sniffed.csv 
```

2) sniffing from Wi-Fi lan without annotation and writing flows to file considering the port addresses:
```
sniff 
    --source        Wi-Fi   
    --interval      0.5   
    --target_file   output/sniffed.csv 
    --use_port      True
```


3) offline generating of network flows (considering ports) from PCAP file with True label annotation and writing flows to file:
```
Convert 
    --source        input/traffic.pcap
    --interval      0.5
    --attacks_time  input/attacker_machine_summary.csv
    --target_file   output/sniffed.csv 
    --use_port      True
```

4) offline generating of network flows from PCAP file with True label annotation and prediction and writing flows to file:
```
Convert 
    --source                input/traffic.pcap
    --interval              0.5
    --attacks_time          input/attacker_machine_summary.csv
    --ids                   input/predict_model.joblib
    --target_file           output/sniffed.csv  
```
or 
```
Convert  --source  input/traffic.pcap --interval 0.5 --attacks  input/attacker_machine_summary.csv  --target_file  output/sniffed.csv 
```

5) offline generating of network flows from PCAP file with True label annotation and prediction and sending them to both target file and MQTT server with credential:
```
Convert 
    --source                    input/traffic.pcap
    --interval                  0.5
    --attacks_time              input/attacker_machine_summary.csv
    --ids                       input/predict_model.joblib
    --target_file               output/sniffed.csv 
    --target_connection         sample_connection.txt
```

6) offline generating of network flows from PCAP file (considering ports) with Packet label annotation and  sending them to both target file and MQTT server with credential:
```
Convert 
    --source                    input/Tow/train.pcap
    --interval                  0.5
    --attacks_packet            input/Tow/y_train.csv
    --use_port                  True
    --target_file               output/sniffed_tow.csv 
    --target_connection         sample_connection.txt
```
