
# ICSFLowGenerator in Docs

This is tool for offline and online processing of network packets and creating network flows.



## Capabilities
Reading packets could be done in two modes
* offline from PCAP file
* online sniffing of LAN

We can annotate data using True labels or predicted labels
* Ture Labels: proving attack history log files, it can detect which flows are malicious
* Predicated Labels: We could also try to analyze network flows with pretrained model and predict its anomality. 


## Arguments 
positional arguments:  <action:sniff|convert>
                        Choose online sniffing of a LAN or offline converting
                        PCAP file

options:
  -h, --help            show this help message and exit
  --source <source file or LAN name>>
                        In online sniffing provide <LAN name> and in offline
                        converting provide <PCAP file>
  --interval interval in seconds
                        interval to compute flows
  --attacks attack log csv file address
                        attack file address for finding true flows' label
  --predictor model      address of pre trained ml model to classify incoming
                        flows
  --target_stream <Stream address>
                        Target server address to stream out network flows
  --target_file <csv file name>
                        csv file to output


## Sample runtime arguments
1) sniffing from Wi-Fi lan without annotation and writing flows to file:
```
sniff --source   Wi-Fi   --interval   0.5   --target_file   output/sniffed.csv 
```


2) offline generating of network flows from PCAP file with True label annotation and writing flows to file::
```
Convert 
    --source        input/traffic.pcap
    --interval      0.5
    --attacks       input/attacker_machine_summary.csv
    --target_file   output/sniffed.csv 
```

3) offline generating of network flows from PCAP file with True label annotation and prediction and writing flows to file:
```
Convert 
    --source                input/traffic.pcap
    --interval              0.5
    --attacks               input/attacker_machine_summary.csv
    --predictor             input/predict_model.joblib
    --target_file           output/sniffed.csv  
```
or 
```
Convert  --source  input/traffic.pcap --interval 0.5 --attacks  input/attacker_machine_summary.csv  --target_file  output/sniffed.csv 
```

4) offline generating of network flows from PCAP file with True label annotation and prediction and sending them to both target file and MQTT server with credential:
```
Convert 
    --source                    input/traffic.pcap
    --interval                  0.5
    --attacks                   input/attacker_machine_summary.csv
    --predictor                 input/predict_model.joblib
    --target_file               output/sniffed.csv 
    --target_connection         sample_connection.txt
```
