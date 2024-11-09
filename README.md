# Security Audit Script

A Bash script designed to detect suspicious activities and potential intrusions on Linux and macOS systems. This script checks system logs, running processes, network connections, file integrity, and installed software to identify potential security threats.

## Features

- **Monitors Failed Login Attempts**: Detects failed login attempts based on system logs.
- **Suspicious Process Detection**: Identifies suspicious processes running on the system.
- **Network Activity Monitoring**: Checks for unusual network connections from known suspicious IPs.
- **File Integrity Check**: Monitors critical system files (`/etc/passwd`, `/etc/ssh/sshd_config`, etc.) for unauthorized changes.
- **Suspicious Software Detection**: Identifies suspicious software installations using `apt`, `yum`, or `brew` based on the system's package manager.
- **Real-Time Alerts**: Logs alerts for suspicious activities into a log file (`suspicious.log`).
- **Parallel Execution**: Optimized for faster execution using parallel checks.

## Prerequisites

- **Linux** or **macOS** system.
- **Bash** shell (default on most Unix-like systems).
- **Root or sudo privileges** for accessing system logs and directories.
- **Internet connection** to monitor suspicious IP ranges and check installed software via package managers.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/security-audit-script.git
cd security-audit-script
```

### 2. Give execute permissions to the script
Ensure the script is executable:

```bash
chmod +x security_audit.sh
```

### Usage:
## Run the Script
To execute the script, run it with root or sudo privileges to access system files and logs:
```bash
sudo ./security_audit.sh
```

The script will:
Check for failed login attempts.
Detect suspicious processes.
Monitor network connections for suspicious IPs.
Verify the integrity of critical system files.
Check for suspicious software installations.


## View Logs
The script logs all suspicious activities in a log file called suspicious.log, which will be saved in the current directory from where the script was executed. You can view the log file using:
```bash
cat suspicious.log
```

## Script Output
The script prints progress to the console, showing the checks being performed (e.g., checking for failed login attempts, monitoring processes).
Alerts for suspicious activities are logged in the suspicious.log file.
After execution, the script logs the time taken to complete the checks.


## Configuration
You can customize the script by modifying the following variables:

- PROCESSES_TO_MONITOR: Add or remove suspicious processes you want to monitor.
- CRITICAL_FILES: List the critical files that should be checked for integrity.
- SUSPICIOUS_IPS: Add suspicious IP ranges to monitor for unusual network connections.
- SUSPICIOUS_SOFTWARE: Add software packages you want to check for suspicious installations.
- MAX_FAILED_LOGINS: Set a threshold for the number of failed login attempts before triggering an alert.
- NETWORK_INTERFACE: Specify the network interface (e.g., eth0, en0 for macOS) for monitoring network activity.


## Contributing
Feel free to fork the repository, open issues, and submit pull requests. If you find bugs or want to add new features, please create a detailed issue or contribute directly to the code!

## License
This project is licensed under the MIT License - see the LICENSE file for details.



### Key Sections in the `README.md`:

- **Features**: Lists the capabilities of the script.
- **Prerequisites**: Describes the environment requirements for running the script.
- **Installation**: How to clone the repository and prepare the script for execution.
- **Usage**: Steps to run the script and view the logs.
- **Scheduled Checks**: How to automate script execution using `cron`.
- **Configuration**: Details on customizing the script's behavior by modifying variables.
- **Contributing**: Encouragement for others to contribute or report issues.
- **License**: An optional section (if applicable, such as MIT License) for legal information.

You can now copy this into a `README.md` file in your project repository, and it will be properly formatted and ready for others to use and understand your script! Let me know if you'd like any more modifications!
