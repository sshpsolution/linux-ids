#!/bin/bash

# Configurations
LOG_FILE="./suspicious.log"  # Log file will be created in the current working directory
PROCESSES_TO_MONITOR=("rootkit" "rkhunter" "ld.so" "metasploit" "moria" "cowrie" "empire" "xmr-stak" "minerd" "cpuminer" "ethminer" \
"nc" "ncat" "socat" "telnetd" "sshd" "backdoor.sh" "nmap" "hydra" "aircrack-ng" "ettercap" "tcpdump" "wireshark" \
"bind" "dnsmasq" "snmpd" "apache2" "nginx" "cron" "atd" "init" "systemd" "systemctl")  # List of suspicious processes
CRITICAL_FILES=("/etc/passwd" "/etc/shadow" "/etc/ssh/sshd_config")  # Files to monitor for changes
SUSPICIOUS_IPS=("1.0.1.0/24" "220.181.0.0/16" "61.0.0.0/8" "5.255.255.0/24" "213.87.0.0/16" "95.213.0.0/16" \
"175.45.176.0/22" "200.200.0.0/16" "177.70.0.0/16" "201.20.0.0/16" "188.72.0.0/16" "194.44.0.0/16" \
"5.250.0.0/16" "80.80.0.0/16" "188.72.0.0/16" "194.44.0.0/16" "23.0.0.0/8" "8.8.8.0/24")  # Suspicious IP ranges

# Path to log the suspicious activity (current directory)
SUSPICIOUS_LOG="./suspicious.log"

# Threshold for failed login attempts
MAX_FAILED_LOGINS=5

# Network interface to monitor
NETWORK_INTERFACE="en0"  # Default network interface on macOS, adjust for your system

# List of suspicious files or directories (e.g., backdoors, rootkits, malicious software)
SUSPICIOUS_FILES=("/usr/local/bin/eviltool" "/opt/malicious" "/tmp/backdoor.sh" "/Applications/WeirdApp.app")  # Suspicious files to check

# List of suspicious software installation via package managers (Homebrew, apt, yum)
SUSPICIOUS_SOFTWARE=("malicious_package" "evil_software" "rootkit_tool" "phishing_tool" "dark_comet" "recon_ng" "rsync" "nc" "metasploit" "hydra" "aircrack-ng" "john")  # Expanded suspicious software list

# Start timer to track execution time
SECONDS=0

# Function to detect failed login attempts
check_failed_logins() {
    echo "Checking for failed login attempts..." >> $SUSPICIOUS_LOG
    FAILED_LOGINS=$(grep "Failed password" $LOG_FILE | wc -l)
    if [[ $FAILED_LOGINS -ge $MAX_FAILED_LOGINS ]]; then
        echo "$(date) - ALERT: $FAILED_LOGINS failed login attempts detected!" >> $SUSPICIOUS_LOG
    else
        echo "$(date) - No failed login attempts detected." >> $SUSPICIOUS_LOG
    fi
}

# Function to check for suspicious processes
check_suspicious_processes() {
    echo "Checking for suspicious processes..." >> $SUSPICIOUS_LOG
    FOUND=false
    for process in "${PROCESSES_TO_MONITOR[@]}"; do
        ps aux | grep -i $process | grep -v grep
        if [[ $? -eq 0 ]]; then
            echo "$(date) - ALERT: Suspicious process $process found!" >> $SUSPICIOUS_LOG
            FOUND=true
        fi
    done
    if [ "$FOUND" = false ]; then
        echo "$(date) - No suspicious processes found." >> $SUSPICIOUS_LOG
    fi
}

# Function to monitor network activity
check_network_activity() {
    echo "Checking for unusual network connections..." >> $SUSPICIOUS_LOG
    CURRENT_CONNECTIONS=$(netstat -an | grep $NETWORK_INTERFACE | grep -E "ESTABLISHED|SYN_SENT")
    FOUND=false
    for ip in "${SUSPICIOUS_IPS[@]}"; do
        echo "$CURRENT_CONNECTIONS" | grep $ip
        if [[ $? -eq 0 ]]; then
            echo "$(date) - ALERT: Suspicious connection from $ip detected!" >> $SUSPICIOUS_LOG
            FOUND=true
        fi
    done
    if [ "$FOUND" = false ]; then
        echo "$(date) - No suspicious network connections found." >> $SUSPICIOUS_LOG
    fi
}

# Function to check file integrity
check_file_integrity() {
    echo "Checking file integrity..." >> $SUSPICIOUS_LOG
    FOUND=false
    for file in "${CRITICAL_FILES[@]}"; do
        if [[ -f $file ]]; then
            CURRENT_CHECKSUM=$(shasum $file)
            PREVIOUS_CHECKSUM=$(cat "/tmp/$(basename $file).checksum" 2>/dev/null)
            
            if [[ "$CURRENT_CHECKSUM" != "$PREVIOUS_CHECKSUM" ]]; then
                echo "$(date) - ALERT: $file has been modified!" >> $SUSPICIOUS_LOG
                echo $CURRENT_CHECKSUM > "/tmp/$(basename $file).checksum"
                FOUND=true
            fi
        fi
    done
    if [ "$FOUND" = false ]; then
        echo "$(date) - No file integrity issues detected." >> $SUSPICIOUS_LOG
    fi
}

# Function to check for suspicious files or directories
check_suspicious_files() {
    echo "Checking for suspicious files and directories..." >> $SUSPICIOUS_LOG
    FOUND=false
    for file in "${SUSPICIOUS_FILES[@]}"; do
        if [[ -e $file ]]; then
            echo "$(date) - ALERT: Suspicious file or directory found: $file" >> $SUSPICIOUS_LOG
            FOUND=true
        fi
    done
    if [ "$FOUND" = false ]; then
        echo "$(date) - No suspicious files or directories found." >> $SUSPICIOUS_LOG
    fi
}

# Function to check for suspicious software installation based on the OS
check_suspicious_software() {
    echo "Checking for suspicious software installations..." >> $SUSPICIOUS_LOG
    FOUND=false

    # Detecting OS type and using the respective package manager
    if [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu-based systems (apt)
        echo "Detected Debian/Ubuntu-based system. Checking with apt..." >> $SUSPICIOUS_LOG
        for software in "${SUSPICIOUS_SOFTWARE[@]}"; do
            if dpkg -l | grep -q $software; then
                echo "$(date) - ALERT: Suspicious software $software installed via apt!" >> $SUSPICIOUS_LOG
                FOUND=true
            fi
        done
    elif [[ -f /etc/redhat-release ]]; then
        # Red Hat/CentOS-based systems (yum)
        echo "Detected Red Hat/CentOS-based system. Checking with yum..." >> $SUSPICIOUS_LOG
        for software in "${SUSPICIOUS_SOFTWARE[@]}"; do
            if yum list installed | grep -q $software; then
                echo "$(date) - ALERT: Suspicious software $software installed via yum!" >> $SUSPICIOUS_LOG
                FOUND=true
            fi
        done
    elif [[ -x "$(command -v brew)" ]]; then
        # macOS (Homebrew)
        echo "Detected macOS. Checking with Homebrew..." >> $SUSPICIOUS_LOG
        for software in "${SUSPICIOUS_SOFTWARE[@]}"; do
            if brew list | grep -q $software; then
                echo "$(date) - ALERT: Suspicious software $software installed via Homebrew!" >> $SUSPICIOUS_LOG
                FOUND=true
            fi
        done
    fi

    if [ "$FOUND" = false ]; then
        echo "$(date) - No suspicious software installations found." >> $SUSPICIOUS_LOG
    fi
}

# Create the log file if it does not exist
if [[ ! -f $SUSPICIOUS_LOG ]]; then
    touch $SUSPICIOUS_LOG
    chmod 644 $SUSPICIOUS_LOG
fi

# Run checks in parallel
check_failed_logins &
check_suspicious_processes &
check_network_activity &
check_file_integrity &
check_suspicious_files &
check_suspicious_software &

# Wait for all background processes to complete
wait

# Log execution time
execution_time=$SECONDS
echo "$(date) - Script execution time: $execution_time seconds." >> $SUSPICIOUS_LOG
echo "Script executed in $execution_time seconds."

