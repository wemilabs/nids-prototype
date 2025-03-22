# NIDS Prototype

This is a prototype of a Network Intrusion Detection System (NIDS) that detects and alerts on common network attacks including port scans and SYN floods.

Read the full blog post here: <a href="https://cuttypiedev.vercel.app/blog/network-intrusion-analysis-part-3-nids-prototype" target="_blank">Network Intrusion Analysis - Part 3: NIDS Prototype</a>

## Overview

This NIDS prototype uses `Scapy` to capture and analyze network packets in real-time, implementing two detection mechanisms:

1. **Port Scan Detection**: Identifies when a source IP attempts to connect to multiple ports on a destination IP within a specified time window.
2. **SYN Flood Detection**: Identifies when a destination IP and port receives an unusually high number of TCP SYN packets, indicating a potential denial-of-service attack.

## Project Structure

The project is organized by network interface:

```
nids-prototype/
├── README.md
├── eth0/               # Implementation for the eth0 interface
│   ├── nids_prototype.py
│   ├── port_scan.py
│   └── syn_flood.py
└── lo/                 # Implementation for the loopback interface
    ├── nids_prototype.py
    ├── port_scan.py
    └── syn_flood.py
```

## Prerequisites

- `Python 3.6 or higher`
- `Scapy` library

## Setup

1. Install the required dependencies:

   ```
   pip install scapy
   ```

2. Choose the appropriate network interface implementation:
   - Use the `eth0` directory for monitoring external network traffic
   - Use the `lo` directory for testing on the loopback interface

## Usage

### Running the NIDS

To monitor the eth0 interface:

```
cd eth0
python nids_prototype.py
```

To monitor the loopback interface (useful for local testing):

```
cd lo
python nids_prototype.py
```

### Testing with Attack Simulations

#### Port Scan Simulation

To simulate a port scan (adjust target IP in script first):

```
python port_scan.py
```

The simulation will attempt to connect to 15 different ports on the target IP.

#### SYN Flood Simulation

To simulate a SYN flood attack (adjust target IP in script first):

```
python syn_flood.py
```

The simulation will send 150 SYN packets to port 80 on the target IP.

## Configuration

The detection parameters can be modified in the `nids_prototype.py` file:

- `TIME_WINDOW`: The time window in seconds for monitoring (default: 60)
- `PORT_THRESHOLD`: Maximum number of unique ports before flagging a port scan (default: 10)
- `SYN_THRESHOLD`: Maximum number of SYN packets before flagging a SYN flood (default: 100)

## How It Works

### Port Scan Detection

The system keeps track of all destination ports a source IP connects to within the specified time window. If the number of unique ports exceeds the threshold, it raises an alert and resets the counter.

### SYN Flood Detection

The system monitors SYN packets (TCP packets with only the SYN flag set) directed at each destination `IP:port` pair. If the number of SYN packets within the time window exceeds the threshold, it raises an alert and resets the counter.

## Limitations

- This is a prototype and not intended for production use
- Detection is based on simple thresholds and may generate false positives/negatives
- Does not persist alerts or provide a management interface

## Future Improvements for Production-Ready

- Persistence for alerts
- Management interface
- More advanced detection mechanisms
- More advanced visualization
