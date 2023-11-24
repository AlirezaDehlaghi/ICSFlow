
# ICSFLowGenerator

This is tool for offline and online processing of network packets and creating network flows.

## Sample runtime arguments
1) sniffing from lan without annotation:
```
sniff --source   Wi-Fi   --interval   0.5   --target_file   output/sniffed.csv 
```

2) offline genering of network flows from PCAP file with True label annotation:
```
Convert 
    --source        input/traffic.pcap
    --interval      0.5
    --attacks       input/attacker_machine_summary.csv
    --target_file   output/sniffed.csv 
```
or 
```
Convert  --source  input/traffic.pcap --interval      0.5 --attacks       input/attacker_machine_summary.csv  --target_file   output/sniffed.csv 
```

