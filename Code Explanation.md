
## Code Explanation 

---

### 1. Basic Setup

```python
WINDOW_SIZE = 10
packet_no = 0
```

* **WINDOW_SIZE** → Defines a 10-second time window for analysis
* The system resets tracking data every 10 seconds
* This ensures detection is based on *rate of traffic*, not total traffic

---

### 2. SnifferState Class

```python
self.ip_counts = {}
self.port_scans = {}
self.multi_scans = {}
self.syn_counts = {}
```

These variables are used to track network behavior:

* **ip_counts** → Number of packets received from each IP
* **port_scans** → Number of hits on the same port
* **multi_scans** → Tracks how many different ports an IP accesses
* **syn_counts** → Counts SYN packets (used in attacks)

This class acts as the *memory* of the intrusion detection system.

---

### 3. Time Window Reset Logic

```python
if current_time - self.window_start > WINDOW_SIZE:
```

* Resets all tracking data after 10 seconds
* Important because attacks are detected based on *activity per time window*, not total traffic

---

### 4. Packet Processing (Main Logic)

```python
def process_packet(packet):
```

* This function runs for every captured packet
* It extracts packet information and checks for suspicious patterns

---

### 5. IP Layer Detection

```python
state.ip_counts[src_ip] += 1
```

* Counts how many packets come from a single IP
* If the count becomes too high → **FLOOD attack detected**

Example:

* Normal: ~10 packets/sec
* Suspicious: 100+ packets/sec

---

### 6. TCP & SYN Flood Detection

```python
if packet[TCP].flags == "S":
```

* SYN packets are used to initiate TCP connections
* Too many SYN packets from one IP → **SYN Flood Attack**

---

### 7. Port Scan Detection

#### Same Port Flood

```python
if state.port_scans[key] > 20:
```

* Detects repeated access to the same port
* Indicates possible **port flooding**

#### Multiple Port Scan

```python
if len(state.multi_scans[src_ip]) > 10:
```

* If one IP accesses many different ports
* Indicates **port scanning activity**

---

### 8. Payload Inspection

```python
if "password" in payload:
```

* Checks packet data for sensitive keywords
* If found → raises alert for possible data leakage

---

### 9. Output Format

```python
print(...)
```

Displays:

* Time
* Packet number
* Source IP
* Destination IP
* Protocol
* Alerts (if any)

---

### 10. Logging System

```python
log_file.write(...)
```

* Saves packet details into a file
* Useful for later analysis and debugging

---

### 11. Sniffer Start Function

```python
sniff(prn=process_packet)
```

* Starts capturing packets continuously
* Each packet is passed to `process_packet()`

---

### 12. Command Line Support

```python
python sniffer.py 100
```

* Captures 100 packets and stops
* If `0` is used → runs continuously

---

## Overall Concept

This project works as a basic **Intrusion Detection System (IDS)**:

* Monitors network traffic in real time
* Detects suspicious patterns
* Generates alerts for potential attacks

---

