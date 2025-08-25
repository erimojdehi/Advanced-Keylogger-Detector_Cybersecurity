# Advanced-Keylogger-Detector_Cybersecurity
Advanced GUI-based Active Keylogger Detector

Advanced Keylogger Detector
===========================

Purpose
-------
This project provides an **advanced GUI-based Active Keylogger Detector** designed to identify suspicious 
processes that exhibit behavior similar to keyloggers. It was developed as the defensive counterpart to a 
proof-of-concept keylogger project, serving as a **practical and advanced security tool for educational 
and research use**.

Unlike simple detectors that only check for known filenames or registry keys, this program uses a 
**multi-signal heuristic approach** combined with **runtime monitoring** to identify active keylogging 
behavior in real time.


How It Works
------------
The program scans all active processes on the system and applies a scoring system based on multiple heuristics. 
Processes that accumulate a high enough score are flagged as suspicious. The user can then review, 
terminate, and optionally delete these processes.

### Detection Methods
1. **Whitelist Filtering**
   - Known safe processes (e.g., `explorer.exe`, `chrome.exe`, `steam.exe`, `msedge.exe`) are ignored.

2. **Suspicious Directories**
   - Flags executables running from directories such as `%APPDATA%`, `%TEMP%`, or `startup`.

3. **Logging Behavior**
   - Detects if the process has `.txt` or `.log` files open.
   - Identifies recent file activity (e.g., modified log files in the last 10–60 seconds).
   - Detects **live logging behavior** where files are actively updated.

4. **Executable Properties**
   - Checks whether the executable is signed (unsigned files raise suspicion).
   - Flags processes that appear to be "headless" (running without a parent like `explorer.exe` or `cmd.exe`).

5. **Scoring**
   - Each suspicious behavior adds to the process score.
   - Processes with a score of 3 or more are flagged as suspicious.

6. **User Cleanup**
   - The interface allows users to:
     - **Kill suspicious processes**
     - **Delete executable files** associated with those processes


Graphical User Interface
-------------------------
The detector is equipped with a full GUI built with **Tkinter**:

- **Start Scan** button: Initiates the scan in a separate thread.
- **Stop Scan** button: Cancels an ongoing scan.
- **Progress Bar**: Displays scan completion percentage.
- **Time Tracker**: Shows elapsed scan time.
- **Log Window**: Scrollable output log that records all scan activity and findings.
- **Suspicious Process List**: Checkboxes to select flagged processes for deletion or termination.


Strengths
---------
- **Advanced multi-factor detection**: combines file system activity, process traits, and runtime monitoring.
- **Whitelist** ensures common safe processes are not flagged.
- **Real-time detection** of `.txt`/`.log` file writes.
- GUI-based, making it accessible for technical and non-technical users alike.
- Effective against simple and educational keyloggers, including the KeyloggerActivator PoC.


Limitations
-----------
- Detects only **user-space keyloggers**; cannot detect kernel-mode or rootkit-level keyloggers.
- Signed but malicious executables may bypass the signature check.
- Relies on heuristic scoring; highly advanced stealth malware may evade detection.
- File deletion may fail if the process is protected or requires elevated privileges.

This is an **advanced detector within the user-space domain**, but is not designed to replace full-scale 
endpoint protection or kernel-level defenses.


Ethics & Legal Notice
---------------------
This tool was created for **educational and defensive purposes** only. 
It is intended to demonstrate practical approaches to detecting suspicious keylogger behavior. 

- Do not misuse this tool for unauthorized surveillance. 
- Running it on systems you do not own or manage with explicit consent is illegal.


Citation
--------
  title  = {Advanced Keylogger Detector: Multi-Signal Process Monitoring Tool},
  author = {Eri Mojdehi},
  url    = {https://github.com/erimojdehi/Advanced-Keylogger-Detector_Cybersecurity},
  note   = {Educational research and defensive tooling}
