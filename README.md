Network Packet Sniffer with Basic Intrusion Detection — Resume Project Description
Project Summary

Developed a command-line based Network Packet Sniffer using Python and Scapy to monitor real-time network traffic and detect suspicious activities. The system captures packets, analyzes protocols, and applies rule-based detection techniques (within a time window) to identify potential threats such as flooding, port scanning, and sensitive data exposure.

Key Contributions
Implemented real-time packet capture using Scapy for low-level network analysis
Designed a time-window based detection system to analyze traffic patterns efficiently
Built rule-based intrusion detection for:
Flood attacks (high packet rate from a single IP)
SYN flood attacks (excessive TCP SYN packets)
Port scanning (multiple ports accessed by same IP)
Port flooding (repeated access to same port)
Integrated payload inspection to detect sensitive keywords (e.g., "password")
Developed structured logging system to store captured packet data in a file
Designed terminal-based tabular output for clear visualization
Features
Live packet capture and monitoring
Protocol identification (TCP, UDP, ICMP)
Source/Destination IP and port tracking
Real-time alert generation
Time-window based anomaly detection
Log file generation for analysis
Command-line argument support
Tech Stack
Python
Scapy (Packet Sniffing & Network Analysis)
Time module (window-based detection)
File handling (logging)
Learning Outcomes
Gained practical understanding of network protocols (TCP, UDP, ICMP)
Learned packet-level analysis and traffic monitoring
Implemented basic Intrusion Detection System (IDS) logic
Improved debugging and performance optimization skills
Understood real-world cybersecurity concepts like flooding and port scanning
Future Improvements
Add GUI dashboard for visualization
Integrate machine learning for advanced anomaly detection
Implement packet filtering (BPF filters)
Add geo-IP tracking and threat intelligence APIs
Real-time alerts via email or notifications
