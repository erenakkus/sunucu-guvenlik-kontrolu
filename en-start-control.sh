#!/bin/bash

# Defining colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
WHITE='\033[0m'

# Saturn drawing
clear
echo -e "${BLUE}
               _______
         _.-'       \`-._
       .'               \`.
     _/                   \_
    /  .-"""-.     .-"""-.  \
   /  /       \   /       \  \
  |   |       |   |       |   |
  |   |       |   |       |   |
   \  \       /   \       /  /
    \_`._   .'     `._   _.'
       \`-._         _.-'
           \`-.___.-' 
  ${GREEN}DESIGNED BY EREN (G4L1LEO) AKKUŞ™${WHITE}
"

# Asking user for language choice
echo -e "${BLUE}Select Language: (1) Turkish (2) English${WHITE}"
read -p "Choose your option (1/2): " LANG_CHOICE

# If Turkish is selected
if [ "$LANG_CHOICE" -eq 1 ]; then
    LANG="TR"
    message_turkish() {
        echo -e "$1"
    }
elif [ "$LANG_CHOICE" -eq 2 ]; then
    LANG="EN"
    message_english() {
        echo -e "$1"
    }
else
    echo -e "${RED}Invalid selection!${WHITE}"
    exit 1
fi

# Function: Printing messages slowly
print_message() {
    if [ "$LANG" == "TR" ]; then
        message_turkish "$1"
    else
        message_english "$1"
    fi
    sleep 1  # Wait for 1 second
}

# Printing system info
SYSTEM_INFO=$(uname -a)
IP_INFO=$(hostname -I | awk '{print $1}')
HOSTNAME=$(hostname)

print_message "${BLUE}Operating System: $SYSTEM_INFO${WHITE}"
print_message "${BLUE}IP Address: $IP_INFO${WHITE}"
print_message "${BLUE}Computer Name: $HOSTNAME${WHITE}"

# Checking system type
if [ -f /etc/debian_version ]; then
    DISTRO="Debian"
    print_message "${BLUE}Debian-based system detected.${WHITE}"
elif [ -f /etc/redhat-release ]; then
    DISTRO="RHEL"
    print_message "${BLUE}RHEL-based system detected.${WHITE}"
else
    print_message "${RED}Unsupported system!${WHITE}"
    exit 1
fi

# Starting message
print_message "${BLUE}Starting checks...${WHITE}"

# 1. SSH Configuration
print_message "${BLUE}Checking SSH Configuration...${WHITE}"

# Root login status
ROOT_LOGIN=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$ROOT_LOGIN" != "no" ]; then
    print_message "${RED}ERROR: Root login is enabled!${WHITE}"
    print_message "${RED}Solution: Open /etc/ssh/sshd_config and change 'PermitRootLogin no'.${WHITE}"
else
    print_message "${GREEN}OK: Root login is disabled.${WHITE}"
fi

# Password authentication
PASSWORD_AUTH=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$PASSWORD_AUTH" != "no" ]; then
    print_message "${RED}ERROR: Password authentication is enabled!${WHITE}"
    print_message "${RED}Solution: Open /etc/ssh/sshd_config and change 'PasswordAuthentication no'.${WHITE}"
else
    print_message "${GREEN}OK: Password authentication is disabled.${WHITE}"
fi

# Default port usage
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$SSH_PORT" == "22" ]; then
    print_message "${YELLOW}Warning: SSH is running on the default port 22!${WHITE}"
    print_message "${YELLOW}Solution: Change the SSH port by entering a new port number in /etc/ssh/sshd_config.${WHITE}"
else
    print_message "${GREEN}OK: SSH port is changed.${WHITE}"
fi

# 2. Firewall Status Check
print_message "${BLUE}Checking Firewall Status...${WHITE}"

if [ "$DISTRO" == "Debian" ]; then
    UFW_STATUS=$(ufw status | grep "Status" | awk '{print $2}')
    if [ "$UFW_STATUS" != "active" ]; then
        print_message "${RED}ERROR: UFW is not active!${WHITE}"
        print_message "${RED}Solution: Activate UFW. Command: sudo ufw enable${WHITE}"
    else
        print_message "${GREEN}OK: UFW is active.${WHITE}"
    fi
elif [ "$DISTRO" == "RHEL" ]; then
    FIREWALL_STATUS=$(systemctl is-active firewalld)
    if [ "$FIREWALL_STATUS" != "active" ]; then
        print_message "${RED}ERROR: Firewalld is not active!${WHITE}"
        print_message "${RED}Solution: Activate Firewalld. Command: sudo systemctl enable --now firewalld${WHITE}"
    else
        print_message "${GREEN}OK: Firewalld is active.${WHITE}"
    fi
else
    print_message "${RED}Firewall type not detected.${WHITE}"
fi

# 3. Fail2ban Configuration
print_message "${BLUE}Checking Fail2ban Configuration...${WHITE}"

FAIL2BAN_STATUS=$(systemctl is-active fail2ban)
if [ "$FAIL2BAN_STATUS" != "active" ]; then
    print_message "${RED}ERROR: Fail2ban is not active!${WHITE}"
    print_message "${RED}Solution: Activate Fail2ban. Command: sudo systemctl enable --now fail2ban${WHITE}"
else
    print_message "${GREEN}OK: Fail2ban is active.${WHITE}"
fi

# 4. Update Status
print_message "${BLUE}Checking System Updates...${WHITE}"

if [ "$DISTRO" == "Debian" ]; then
    UPDATE_STATUS=$(apt-get -s upgrade | grep "upgraded,")
    if [ -z "$UPDATE_STATUS" ]; then
        print_message "${GREEN}OK: System is up to date.${WHITE}"
    else
        print_message "${RED}ERROR: Updates available!${WHITE}"
        print_message "${RED}Solution: Update the system. Command: sudo apt-get update && sudo apt-get upgrade${WHITE}"
    fi
elif [ "$DISTRO" == "RHEL" ]; then
    UPDATE_STATUS=$(yum check-update | grep "updates")
    if [ -z "$UPDATE_STATUS" ]; then
        print_message "${GREEN}OK: System is up to date.${WHITE}"
    else
        print_message "${RED}ERROR: Updates available!${WHITE}"
        print_message "${RED}Solution: Update the system. Command: sudo yum update${WHITE}"
    fi
fi

# 5. Performance Monitoring
print_message "${BLUE}Checking Performance Status...${WHITE}"

# Disk Usage
DISK_SPACE=$(df -h / | grep -v Filesystem | awk '{print $5}')
print_message "${BLUE}Disk Space Usage: $DISK_SPACE${WHITE}"

# Memory Usage
MEMORY_USAGE=$(free -h | grep Mem | awk '{print $3 "/" $2}')
print_message "${BLUE}Memory Usage: $MEMORY_USAGE${WHITE}"

# CPU Usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
print_message "${BLUE}CPU Usage: $CPU_USAGE%${WHITE}"

# 6. Security Tips and Solutions
print_message "${GREEN}OK: Security and performance checks completed.${WHITE}"

# Solutions:
print_message "${GREEN}Actions to take:${WHITE}"
print_message "${GREEN}- Disable SSH root login and turn off password authentication.${WHITE}"
print_message "${GREEN}- Change the default SSH port.${WHITE}"
print_message "${GREEN}- Enable UFW (Debian) or Firewalld (RHEL).${WHITE}"
print_message "${GREEN}- Enable Fail2ban.${WHITE}"
print_message "${GREEN}- Regularly update the system.${WHITE}"

# Asking user whether to apply updates automatically
print_message "${YELLOW}Do you want to apply security updates automatically? (Yes/No)${WHITE}"
read -p "Enter your answer: " UPDATE_ANSWER
if [[ "$UPDATE_ANSWER" == "Yes" || "$UPDATE_ANSWER" == "yes" ]]; then
    print_message "${GREEN}Starting updates...${WHITE}"
    if [ "$DISTRO" == "Debian" ]; then
        sudo apt-get update && sudo apt-get upgrade -y
    elif [ "$DISTRO" == "RHEL" ]; then
        sudo yum update -y
    fi
else
    print_message "${BLUE}Updates skipped.${WHITE}"
fi
