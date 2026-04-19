

##  Code Explanation

### 1. Basic Configuration

* `WINDOW_SIZE = 10` → Defines a 10-second time window for analysis
* `packet_no` → Tracks total number of packets captured
* Detection is based on traffic **rate within a time window**

---

### 2. Sniffer State Management

A class is used to store temporary data for detection:

* `ip_counts` → Number of packets per IP
* `port_scans` → Repeated hits on the same port
* `multi_scans` → Unique ports accessed by an IP
* `syn_counts` → SYN packets count per IP

This acts as the **memory of the system**.

---

### 3. Time Window Reset

* All counters reset after a fixed time interval
* Prevents memory growth
* Ensures detection is **time-based (real-time)**

---

### 4. Packet Processing

* Each captured packet is processed individually
* Extracts:

  * Source IP
  * Destination IP
  * Ports
  * Protocol
* Applies detection rules on each packet

---

### 5. Flood Detection

* Tracks packets from each IP
* If packet count exceeds threshold → **FLOOD alert**

---

### 6. SYN Flood Detection

* Checks TCP SYN flags
* Excessive SYN packets from one IP → **SYN Flood Attack**

---

### 7. Port Scan Detection

* **Same port repeatedly accessed** → Port Flood
* **Multiple ports accessed by same IP** → Port Scanning

---

### 8. Payload Inspection

* Packet data is checked for sensitive keywords
* Example: `"password"`
* If found → **Security alert generated**

---

### 9. Output Display

Displays:

* Time
* Packet number
* Source & Destination IP
* Ports
* Protocol
* Alerts (if detected)

---

### 10. Logging System

* Packet details are saved into a log file
* Useful for analysis and debugging

---

### 11. Packet Capture

* Continuously captures network packets
* Each packet is analyzed in real time

---

##  Overall Working

This project functions as a **basic Intrusion Detection System (IDS)**:

* Monitors live network traffic
* Detects suspicious activities
* Generates alerts based on predefined rules

---

