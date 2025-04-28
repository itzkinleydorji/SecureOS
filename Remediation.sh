#Let's start scripting 
clear
GREEN='\e[1;32m'
BLUE='\e[1;34m'
PINK='\e[1;35m'
PURPLE='\e[0;35m'
YELLOW='\033[0;33m'
CYAN='\e[1;36m'
RED='\e[1;31m'
BROWN='\e[0;33m'
RESET='\e[0m'

cols=$(tput cols)
pad=$(( (cols - 50) / 2 ))
padding=$(printf '%*s' "$pad" '')

printf "${GREEN}%*s╭─────────────────────༺♡༻────────────────────╮${RESET}\n" "$pad" ""
printf "${GREEN}%*s |             WELCOME TO SECUREOS          |${RESET}\n" "$pad" ""
printf "${GREEN}%*s╰─────────────────────༺♡༻────────────────────╯${RESET}\n" "$pad" ""
printf "${BLUE}%*s  Program Version: ${RESET}1.0\n" "$pad" ""
printf "${BLUE}%*s  Developer: ${RESET}Kinley Dorji\n" "$pad" ""
printf "${CYAN}%*s  GitHub: ${RESET}https://github.com/kinleydorji-65${RESET}\n" "$pad" ""
printf "${CYAN}%*s  Terms & Services: ${RESET}Plese read on GitHub${RESET}\n" "$pad" ""
printf "${GREEN}%*s---------------------------------------------${RESET}\n" "$pad" ""

echo -ne "${GREEN}Auditor Name${RESET} (eg. Kinley Dorji): "
read auditor_name
tput cuu1 
tput el
printf "${BLUE}[+] Starting Program${RESET}\n"
printf "═════════════════════════════════════════════\n"
printf " • Detecting OS... "
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    if [[ "$ID_LIKE" =~ "debian" ]]; then
        os_type="Linux"
    elif [[ "$ID_LIKE" =~ "rhel" ]]; then
        os_type="Linux"
    elif [[ "$ID_LIKE" =~ "arch" ]]; then
        os_type="Linux"
    elif [[ "$ID" =~ "windows" ]]; then
        os_type="Windows"
    else
        os_type="$ID"
    fi
    printf "[${GREEN}Detected${RESET}]\n"
else
    os_type="Unknown"
    printf "[${RED}Not Detected${RESET}]\n"
fi
printf " • Checking Profile...[${GREEN}Done${RESET}]\n"
printf "═════════════════════════════════════════════\n"
printf " OS:             [${GREEN}$os_type${RESET}]\n"
printf " OS Name:        [${GREEN}$NAME${RESET}]\n"
printf " OS Version:     [${GREEN}$VERSION${RESET}]\n"
printf " Kernel Version: [${GREEN}$(uname -r)${RESET}]\n"
printf " Hardware Platforms: [${GREEN}$(uname -m)${RESET}]\n"
printf " Hostname:       [${GREEN}$(hostname)${RESET}]\n"
printf " Auditor:        [${GREEN}$auditor_name${RESET}]\n"
printf "═════════════════════════════════════════════\n"
echo -e "${GREEN}Analyzing...${RESET}"
sleep 5
tput cuu1 
tput el

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring filesystem kernel modules${RESET}...\n"
printf "╰─..★.──────────────────────────────────────╯\n"
sleep 5

modules=("cramfs" "vfat" "exfat" "nfs" "cifs" "gfs2" "fuse" "freevxfs" "hfs" "hfsplus" "jffs2" "overlayfs" "squashfs" "udf" "usb-storage")

BLACKLIST_FILE="/etc/modprobe.d/blacklist.conf"

add_blacklist_entry() {
    local module="$1"

    if ! grep -q "^blacklist $module" "$BLACKLIST_FILE"; then
        echo "blacklist $module" | sudo tee -a "$BLACKLIST_FILE" > /dev/null
    else
        echo -e "    ${BLUE}$module is already blacklisted.${RESET}"
    fi
}

if [ ! -f "$BLACKLIST_FILE" ]; then
    echo "Creating blacklist file at $BLACKLIST_FILE..."
    sudo touch "$BLACKLIST_FILE"
fi

kernel_module() {
    local module="$1"

    if lsmod | grep -q "^$module"; then
        sudo modprobe -r "$module"
    fi

    add_blacklist_entry "$module"

    if ! lsmod | grep -q "^$module"; then
        printf " •${YELLOW} Ensuring $module kernel module is not available...${RESET}[${GREEN}Done${RESET}]\n"
    else
        printf " •${YELLOW} Ensuring $module kernel module is not available...${RESET}[${RED}Fail${RESET}]\n"
    fi
}

for module in "${modules[@]}"; do
    kernel_module "$module"
done

echo -e "➽ ${GREEN}Configuring filesystem kernel modules completed${RESET}"
sleep 20

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring filesystem partitions${RESET}...\n"
printf "╰─..★.──────────────────────────────────────╯\n"
sleep 5
echo -e "\n📌 ${BLUE}Recommended Partition Allocation (% of total disk size)${RESET}"
echo "─────────────────────────────────────────────────────────────────────────────────────────────────────────── "
printf "| %-25s | %-20s | %-52s |\n" "Partition" "Recommended %" "Purpose"
echo "───────────────────────────────────────────────────────────────────────────────────────────────────────────"
printf "| %-25s | %-20s | %-52s |\n" "/home" "50%" "User files, personal data, and settings"
printf "| %-25s | %-20s | %-52s |\n" "/var" "20%" "System logs, mail, databases, and package management"
printf "| %-25s | %-20s | %-52s |\n" "/tmp" "5%" "Temporary files used by applications and users"
printf "| %-25s | %-20s | %-52s |\n" "/var/log" "20%" "Logs for auditing, troubleshooting, and monitoring"
printf "| %-25s | %-20s | %-52s |\n" "/var/tmp" "2%" "Temporary files that persist across reboots"
printf "| %-25s | %-20s | %-52s |\n" "/var/log/audit" "3%" "Security audit logs"
printf "| %-25s | %-20s | %-52s |\n" "Other (root, swap)" "20%" "Root filesystem and swap space"
echo "───────────────────────────────────────────────────────────────────────────────────────────────────────────"
echo "● This is a general recommendation. If it's a database or web server, /var might need more space."
echo "● If it's a desktop system, /home should be larger."
echo -e "${RED}Warning! Are you sure you want to continue? This will modify partitions.${RESET} (Y/n)"
read -r confirm
tput cuu1 
tput el

if [[ "$confirm" != "Y" && "$confirm" != "y" ]]; then
    echo "Operation cancelled."
else
    echo -e "\n${BLUE}Your current disk map:${RESET}"
    lsblk
    echo -e "${BROWN}Enter size for /var${RESET} (e.g., 10G for a 100GB disk): "
    read var_size
    echo -e "${BROWN}Enter size for /home${RESET} (e.g., 50G for a 100GB disk): "
    read home_size
    echo -e "${BROWN}Enter size for /tmp${RESET} (e.g., 5G for a 100GB disk): "
    read tmp_size
    echo -e "${BROWN}Enter size for /var/log${RESET} (e.g., 10G for a 100GB disk): "
    read var_log_size
    echo -e "${BROWN}Enter size for /var/tmp${RESET} (e.g., 2G for a 100GB disk): "
    read var_tmp_size
    echo -e "${BROWN}Enter size for /var/log/audit${RESET} (e.g., 3G for a 100GB disk): "
    read var_log_audit_size

    vg_name=$(vgs --noheadings -o vg_name | awk '{print $1}')

    echo -e "${GREEN}Backing up system data${RESET}..."
    mkdir -p /mnt/backup #>/dev/null 2>&1
    for dir in /var /tmp /home /var/log /var/tmp /var/log/audit; do
        rsync -aX "$dir/" "/mnt/backup$(echo "$dir" | sed 's|/|-|g')/"
    done

    for lv in var tmp home var_log var_tmp var_log_audit; do
        lvremove -y /dev/$vg_name/$lv
    done

    lvcreate -L $var_size -n var $vg_name
    lvcreate -L $home_size -n home $vg_name
    lvcreate -L $tmp_size -n tmp $vg_name
    lvcreate -L $var_log_size -n var_log $vg_name
    lvcreate -L $var_tmp_size -n var_tmp $vg_name
    lvcreate -L $var_log_audit_size -n var_log_audit $vg_name

    for lv in var home tmp var_log var_tmp var_log_audit; do
        mkfs.ext4 /dev/$vg_name/$lv
    done

    for dir in var home tmp var_log var_tmp var_log_audit; do
        mkdir -p /mnt/new$dir
        mount /dev/$vg_name/$dir /mnt/new$dir
    done

    for dir in /var /home /tmp /var/log /var/tmp /var/log/audit; do
        rsync -aX "/mnt/backup$(echo "$dir" | sed 's|/|-|g')/" "/mnt/new$(basename "$dir")/"
    done

    for dir in var home tmp var_log var_tmp var_log_audit; do
        umount "/mnt/new$dir"
    done

    vgchange -ay $vg_name

    sed -i '/\/var /d' /etc/fstab
    sed -i '/\/home /d' /etc/fstab
    sed -i '/\/tmp /d' /etc/fstab
    sed -i '/\/var\/log /d' /etc/fstab
    sed -i '/\/var\/tmp /d' /etc/fstab
    sed -i '/\/var\/log\/audit /d' /etc/fstab
    sed -i '/\/dev\/shm /d' /etc/fstab

    cat <<EOF >> /etc/fstab 
/dev/$vg_name/var /var ext4 defaults,nodev,nosuid 0 2
/dev/$vg_name/home /home ext4 defaults,nodev,nosuid 0 2
/dev/$vg_name/tmp /tmp ext4 defaults,nodev,noexec,nosuid 0 2
/dev/$vg_name/var_log /var/log ext4 defaults,nodev,noexec,nosuid 0 2
/dev/$vg_name/var_tmp /var/tmp ext4 defaults,nodev,noexec,nosuid 0 2
/dev/$vg_name/var_log_audit /var/log/audit ext4 defaults,nodev,noexec,nosuid 0 2
tmpfs /dev/shm tmpfs defaults,nodev,noexec,nosuid 0 2
EOF
    rm -rf /mnt/backup 
    mount -a -v 
fi
echo -e "➽ ${GREEN}Configuring partitioning completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring package management${RESET}...\n"
printf "╰─..★.──────────────────────────────────────╯\n"
sleep 5

GPG_STATUS="Done"  

missing_keys=$(apt-key list 2>/dev/null | grep -oP '(?<=NO_PUBKEY )\w+')

if [ -n "$missing_keys" ]; then
    
    for KEY in $missing_keys; do
        if gpg --keyserver hkp://keyserver.ubuntu.com --recv-keys "$KEY" >/dev/null 2>&1; then
            gpg --export --armor "$KEY" | tee "/etc/apt/trusted.gpg.d/$KEY.gpg" >/dev/null
        else
            GPG_STATUS="failed" 
            break
        fi
    done

    if [ "$GPG_STATUS" != "failed" ]; then
        GPG_STATUS="Done"
    fi
fi

if [ "$GPG_STATUS" == "Done" ]; then
    printf " •${YELLOW} Ensure GPG keys are configured...${RESET}[${GREEN}$GPG_STATUS${RESET}]\n"
fi

if apt-cache policy > /dev/null 2>&1; then
    printf " •${YELLOW} Ensure package manager repositories are configured...${RESET}[${GREEN}Done${RESET}]\n"
else
    UBUNTU_VERSION=$(lsb_release -sc)

    sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak 2>/dev/null

    sudo sh -c "grep -q 'http://archive.ubuntu.com/ubuntu $UBUNTU_VERSION main restricted universe multiverse' /etc/apt/sources.list || echo 'deb http://archive.ubuntu.com/ubuntu $UBUNTU_VERSION main restricted universe multiverse' >> /etc/apt/sources.list"
    sudo sh -c "grep -q 'http://archive.ubuntu.com/ubuntu $UBUNTU_VERSION-updates main restricted universe multiverse' /etc/apt/sources.list || echo 'deb http://archive.ubuntu.com/ubuntu $UBUNTU_VERSION-updates main restricted universe multiverse' >> /etc/apt/sources.list"
    sudo sh -c "grep -q 'http://security.ubuntu.com/ubuntu $UBUNTU_VERSION-security main restricted universe multiverse' /etc/apt/sources.list || echo 'deb http://security.ubuntu.com/ubuntu $UBUNTU_VERSION-security main restricted universe multiverse' >> /etc/apt/sources.list"

    sudo apt-get update -y >/dev/null 2>&1

    printf " •${YELLOW} Ensure package manager repositories are configured...${RESET}[${GREEN}Done${RESET}]\n"
fi
# if apt-cache policy > /dev/null 2>&1; then
#     printf " •${YELLOW} Ensure package manager repositories are configured...${RESET}[${GREEN}Done${RESET}]\n"
# else
#     sudo apt-get update && sudo apt-get install -y software-properties-common
#     sudo add-apt-repository -y "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) main restricted universe multiverse"
#     sudo add-apt-repository -y "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc)-updates main restricted universe multiverse"
#     sudo add-apt-repository -y "deb http://security.ubuntu.com/ubuntu $(lsb_release -sc)-security main restricted universe multiverse"
#     sudo apt-get update
#     printf " •${YELLOW} Ensure package manager repositories are configured...${RESET}[${GREEN}Done${RESET}]\n"
# fi

echo -e "➽ ${GREEN}Configuring package management completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭───────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring mandatory access control${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────╯\n"
dpkg-query -s apparmor apparmor-utils &>/dev/null || {
    sudo apt-get update -qq
    sudo apt-get install -y apparmor apparmor-utils >/dev/null 2>&1
}
printf " •${YELLOW} Ensure AppArmor & Apparmor-utils are installed...${RESET}[${GREEN}Done${RESET}]\n"

if grep -q 'apparmor=1' /etc/default/grub; then
    printf " •${YELLOW} Ensure apparmor=1 is set in GRUB_CMDLINE_LINUX ...${RESET}[${GREEN}Done${RESET}]\n"
else
    sudo sed -i 's/^GRUB_CMDLINE_LINUX="/&apparmor=1 /' /etc/default/grub
    printf " •${YELLOW} Ensure apparmor=1 is set in GRUB_CMDLINE_LINUX ...${RESET}[${GREEN}Done${RESET}]\n"
fi

if grep -q 'security=apparmor' /etc/default/grub; then
    printf " •${YELLOW} Ensure security=apparmor is set in GRUB_CMDLINE_LINUX ...${RESET}[${GREEN}Done${RESET}]\n"
else
    sudo sed -i 's/^GRUB_CMDLINE_LINUX="/&security=apparmor /' /etc/default/grub
    printf " •${YELLOW} Ensure security=apparmor is set in GRUB_CMDLINE_LINUX ...${RESET}[${GREEN}Done${RESET}]\n"
fi
sudo update-grub &>/dev/null

sudo aa-enforce /etc/apparmor.d/* &>/dev/null
# sudo aa-complain /etc/apparmor.d/* &>/dev/null
printf " •${YELLOW} Ensure all AppArmor Profiles are in enforce or complain mode ...${RESET}[${GREEN}Done${RESET}]\n"

echo -e "➽ ${GREEN}Configuring mandatory access control completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring bootloader${RESET}...\n"
printf "╰─..★.──────────────────────────────────────╯\n"
sleep 5

read -rp "Enter GRUB superuser username: " USERNAME

while true; do
    read -rsp "Enter GRUB password: " PASSWORD
    echo
    read -rsp "Re-enter GRUB password: " PASSWORD_CONFIRM
    echo
    
    if [[ "$PASSWORD" == "$PASSWORD_CONFIRM" ]]; then
        break
    else
        echo -e "${RED}Passwords do not match. Please try again.${RESET}"
    fi
done

ENCRYPTED_PASSWORD=$(echo -e "$PASSWORD\n$PASSWORD" | grub-mkpasswd-pbkdf2 --iteration-count=600000 --salt=64 2>/dev/null | awk '/PBKDF2/ {print $NF}')

if [[ -z "$ENCRYPTED_PASSWORD" ]]; then
    echo -e "${RED}Failed to generate encrypted password. Exiting.${RESET}"
    exit 1
fi

GRUB_CUSTOM="/etc/grub.d/40_custom"

cat <<EOF > "$GRUB_CUSTOM"
#!/bin/sh
exec tail -n +3 \$0

set superusers="$USERNAME"
password_pbkdf2 $USERNAME $ENCRYPTED_PASSWORD
EOF

chmod 600 "$GRUB_CUSTOM"
chmod +x "$GRUB_CUSTOM"

sed -i '/set superusers=/d' /etc/grub.d/00_header
sed -i '/password_pbkdf2/d' /etc/grub.d/00_header

sed -i 's/CLASS="--class gnu-linux --class gnu --class os"/CLASS="--class gnu-linux --class gnu --class os --unrestricted"/g' /etc/grub.d/10_linux

update-grub >/dev/null 2>&1

printf " •${YELLOW} Ensure bootloader password & username is set...${RESET}[${GREEN}Done${RESET}]\n"

if stat -c "%a" /boot/grub/grub.cfg | grep -q "600" && stat -c "%U" /boot/grub/grub.cfg | grep -q "root" && stat -c "%G" /boot/grub/grub.cfg | grep -q "root"; then
    printf " •${YELLOW} Ensure access to bootloader config is configured...${RESET}[${GREEN}DONE${RESET}]\n"
else
    
    chown root:root /boot/grub/grub.cfg
    chmod u-x,go-rwx /boot/grub/grub.cfg
    printf " •${YELLOW} Ensure access to bootloader config is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi

echo -e "➽ ${GREEN}Configuring bootloader completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring Additional Process Hardening${RESET}...\n"
printf "╰─..★.──────────────────────────────────────────────╯\n"
sleep 5

echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/60-kernel_sysctl.conf
sysctl -w kernel.randomize_va_space=2 > /dev/null 2>&1
sysctl --system > /dev/null 2>&1
printf " •${YELLOW} Ensure address space layout randomization is enabled...${RESET}[${GREEN}DONE${RESET}]\n"

echo "kernel.yama.ptrace_scope = 1" > /etc/sysctl.d/60-kernel_sysctl.conf
sysctl -w kernel.yama.ptrace_scope=1 > /dev/null 2>&1
sysctl --system > /dev/null 2>&1
printf " •${YELLOW} Ensure ptrace_scope is restricted...${RESET}[${GREEN}DONE${RESET}]\n"

if ! grep -qP '^\s*\*\s+hard\s+core\s+0\b' /etc/security/limits.conf 2>/dev/null && 
   ( [ ! -d /etc/security/limits.d ] || ! grep -qP '^\s*\*\s+hard\s+core\s+0\b' /etc/security/limits.d/* 2>/dev/null ); then
    mkdir -p /etc/security/limits.d
    echo "* hard core 0" >> /etc/security/limits.d/99-core-dump.conf
fi

if [[ "$(sysctl fs.suid_dumpable | awk '{print $3}')" -ne 0 ]]; then
    echo "fs.suid_dumpable = 0" > /etc/sysctl.d/60-fs_sysctl.conf
    sysctl -w fs.suid_dumpable=0 > /dev/null 2>&1
    sysctl --system > /dev/null 2>&1
fi
printf " •${YELLOW} Ensure core dumps are restricted...${RESET}[${GREEN}DONE${RESET}]\n"

if dpkg-query -s prelink &>/dev/null; then
  prelink -ua &>/dev/null
  apt purge -y prelink &>/dev/null
  printf " •${YELLOW} Ensure prelink is not installed...${RESET}[${GREEN}DONE${RESET}]\n"
else
  printf " •${YELLOW} Ensure prelink is not installed...${RESET}[${GREEN}DONE${RESET}]\n"
fi

dpkg-query -s apport &>/dev/null
if [ $? -eq 0 ]; then
    
    sed -i 's/^enabled=\(.*\)$/enabled=0/' /etc/default/apport

    systemctl stop apport.service &>/dev/null
    systemctl mask apport.service &>/dev/null

    printf " •${YELLOW} Ensure Automatic Error Reporting is not enabled...${RESET}[${GREEN}DONE${RESET}]\n"
    printf " •${YELLOW} Ensure apport service is not active...${RESET}[${GREEN}DONE${RESET}]\n"
else
    apt purge -y apport &>/dev/null

    printf " •${YELLOW} Ensure apport is removed...${RESET}[${GREEN}DONE${RESET}]\n"
fi
echo -e "➽ ${GREEN}Configuring additional process hardening completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring Command Line Warning Banners${RESET}...\n"
printf "╰─..★.──────────────────────────────────────────────╯\n"
sleep 5

scripts=(
    "/etc/update-motd.d/50-landscape-sysinfo"
    "/etc/update-motd.d/90-updates-available"
    "/etc/update-motd.d/98-reboot-required"
    "/etc/update-motd.d/50-motd-news"
)

for script in "${scripts[@]}"; do
    [ -x "$script" ] && chmod -x "$script"
done

sudo mkdir -p /etc/motd.d

echo "SeOS - Authorized users only. All activity may be monitored and reported." | sudo tee /etc/motd.d/00-custom > /dev/null
sudo chmod 644 /etc/motd.d/00-custom

[ -f "/etc/motd" ] || echo "SeOS - Authorized users only. All activity may be monitored and reported." | sudo tee /etc/motd > /dev/null
sudo chmod 640 /etc/motd

echo -e "SeOS's -${PURPLE}Authorized users only. All activity may be monitored and reported.${RESET}"
echo "Do you want to use SeOS's banner for local login (y) or a custom banner (n)?"
read -r use_default_banner
tput cuu1 
tput el
sed -i '/Ubuntu\|Debian\|Linux/d' /etc/issue
if [ "$use_default_banner" == "y" ]; then
    echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
else
    echo "Enter the local login warning banner text:"
    read -r banner_text
    echo "$banner_text" > /etc/issue
fi
echo "Do you want to use SeOS's banner for remote login (y) or a custom banner (n)?"
read -r use_default_banner
tput cuu1 
tput el
sed -i '/Ubuntu\|Debian\|Linux/d' /etc/issue.net
if [ "$use_default_banner" == "y" ]; then
    echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
else
    echo "Enter the remote login warning banner text:"
    read -r banner_text
    echo "$banner_text" > /etc/issue.net
fi
if ! grep -q "^Banner /etc/issue.net" /etc/ssh/ssh_config; then
    echo "Banner /etc/issue.net" | sudo tee -a /etc/ssh/ssh_config > /dev/null
fi
if systemctl list-units --full --all | grep -q 'ssh.service'; then
    service="ssh"
elif systemctl list-units --full --all | grep -q 'sshd.service'; then
    service="sshd"
else
    echo "No SSH service found. Exiting."
fi
sudo systemctl restart $service > /dev/null 2>&1
sudo chmod 644 /etc/issue
if [ "$(stat -c "%a" /etc/issue)" == "644" ]; then
    printf " •${YELLOW} Ensure access to /etc/issue is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
sudo chmod 644 /etc/issue.net
if [ "$(stat -c "%a" /etc/issue.net)" == "644" ]; then
    printf " •${YELLOW} Ensure access to /etc/issue.net is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
printf " •${YELLOW} Ensure message of the day is configured...${RESET}[${GREEN}DONE${RESET}]\n"
printf " •${YELLOW} Ensure local login warning banner is configured...${RESET}[${GREEN}DONE${RESET}]\n"
printf " •${YELLOW} Ensure remote login warning banner is configured...${RESET}[${GREEN}DONE${RESET}]\n"
printf " •${YELLOW} Ensure access to /etc/motd is configured...${RESET}[${GREEN}DONE${RESET}]\n"
echo -e "➽ ${GREEN}Configuring Command Line Warning Banners completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring GNOME Display Manager${RESET}...\n"
printf "╰─..★.──────────────────────────────────────────╯\n"
sleep 5

if ! dpkg-query -W -f='${Status}\n' gdm3 2>/dev/null | grep -q "installed"; then
    printf " •${YELLOW} Ensure GDM is removed...${RESET}[${GREEN}DONE${RESET}]\n"
fi
apt purge -y gdm3 > /dev/null 2>&1
apt autoremove -y > /dev/null 2>&1
if ! dpkg-query -W -f='${Status}\n' gdm3 2>/dev/null | grep -q "installed"; then
    printf " •${YELLOW} Ensure GDM is removed...${RESET}[${GREEN}DONE${RESET}]\n"
else
    echo "[ERROR] GDM3 removal failed."
fi
echo -e "➽ ${GREEN}Configuring GNOME Display Managers completed${RESET}"
sleep 5

printf "${BLUE}[+] Services${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring Server Services${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5
if ! dpkg-query -s autofs &>/dev/null; then
    printf " •${YELLOW} Ensure autofs services are not in use...${RESET}[${GREEN}DONE${NC}] "
fi
if apt-cache rdepends autofs | grep -qv "Reverse Depends:"; then
    echo "[INFO] autofs is required by other packages. Masking the service instead." > /dev/null 2>&1
    systemctl stop autofs.service > /dev/null 2>&1
    systemctl mask autofs.service > /dev/null 2>&1
else
    echo "[INFO] Removing autofs..." > /dev/null 2>&1
    systemctl stop autofs.service > /dev/null 2>&1
    apt purge -y autofs > /dev/null 2>&1
fi
if ! dpkg-query -s autofs &>/dev/null; then
    echo -e " autofs removed successfully...[${GREEN}DONE${NC}] "
else
    echo -e " autofs masked successfully...[${GREEN}DONE${NC}]"
fi

if ! dpkg-query -s avahi-daemon &>/dev/null; then
    printf " •${YELLOW} Ensure avahi daemon services are not in use...[${GREEN}DONE${NC}] "
fi

if apt-cache rdepends avahi-daemon | grep -qv "Reverse Depends:"; then
    echo "[INFO] avahi-daemon is required by other packages. Masking the service instead." > /dev/null 2>&1
    systemctl stop avahi-daemon.service avahi-daemon.socket > /dev/null 2>&1
    systemctl mask avahi-daemon.service avahi-daemon.socket > /dev/null 2>&1
else
    echo "[INFO] Removing avahi-daemon..." > /dev/null 2>&1
    systemctl stop avahi-daemon.service avahi-daemon.socket > /dev/null 2>&1
    apt purge -y avahi-daemon > /dev/null 2>&1
fi

if ! dpkg-query -s avahi-daemon &>/dev/null; then
    echo -e " avahi-daemon removed successfully...[${GREEN}DONE${NC}] "
else
    echo -e " avahi-daemon masked successfully...[${GREEN}DONE${NC}] "
fi

if ! dpkg-query -s isc-dhcp-server &>/dev/null; then
    printf " •${YELLOW} Ensure dhcp server services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
else
    if apt-cache rdepends isc-dhcp-server | grep -qv "Reverse Depends:"; then
        systemctl stop isc-dhcp-server.service isc-dhcp-server6.service &>/dev/null
        systemctl mask isc-dhcp-server.service isc-dhcp-server6.service &>/dev/null
    else
        systemctl stop isc-dhcp-server.service isc-dhcp-server6.service &>/dev/null
        apt purge -y isc-dhcp-server &>/dev/null
    fi
    if ! dpkg-query -s isc-dhcp-server &>/dev/null; then
        printf " •${YELLOW} Ensure dhcp server services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        printf " •${YELLOW} Ensure dhcp server services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
fi
if dpkg-query -s bind9 &>/dev/null; then
    if apt-cache rdepends bind9 | grep -qv "Reverse Depends:"; then
        systemctl stop named.service &>/dev/null
        systemctl mask named.service &>/dev/null
    else
        systemctl stop named.service &>/dev/null
        apt purge -y bind9 &>/dev/null
    fi
fi
printf " •${YELLOW} Ensure dns server services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s dnsmasq &>/dev/null; then
    if apt-cache rdepends dnsmasq | grep -qv "Reverse Depends:"; then
        systemctl stop dnsmasq.service &>/dev/null
        systemctl mask dnsmasq.service &>/dev/null
    else
        systemctl stop dnsmasq.service &>/dev/null
        apt purge -y dnsmasq &>/dev/null
    fi
fi
printf " •${YELLOW} Ensure dnsmasq services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s vsftpd &>/dev/null; then
    if apt-cache rdepends vsftpd | grep -qv "Reverse Depends:"; then
        systemctl stop vsftpd.service &>/dev/null
        systemctl mask vsftpd.service &>/dev/null
    else
        systemctl stop vsftpd.service &>/dev/null
        apt purge -y vsftpd &>/dev/null
    fi
fi
printf " •${YELLOW} Ensure ftp server services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s slapd &>/dev/null; then        
    if apt-cache rdepends slapd | grep -qv "Reverse Depends:"; then
        systemctl stop slapd.service &>/dev/null
        systemctl mask slapd.service &>/dev/null
    else
        systemctl stop slapd.service &>/dev/null
        apt purge -y slapd &>/dev/null
    fi
fi
printf " •${YELLOW} Ensure ldap server services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"

if dpkg-query -s ypserv &>/dev/null; then
    systemctl stop ypserv.service
    apt purge -y ypserv
elif systemctl is-enabled ypserv.service 2>/dev/null | grep -q 'enabled' || \
     systemctl is-active ypserv.service 2>/dev/null | grep -q '^active'; then
    systemctl stop ypserv.service
    systemctl mask ypserv.service
fi
printf " •${YELLOW} Ensure nis server services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s rpcbind &>/dev/null; then
    systemctl stop rpcbind.socket rpcbind.service
    apt purge -y rpcbind
elif systemctl is-enabled rpcbind.socket rpcbind.service 2>/dev/null | grep -q 'enabled' || \
     systemctl is-active rpcbind.socket rpcbind.service 2>/dev/null | grep -q '^active'; then
    systemctl stop rpcbind.socket rpcbind.service
    systemctl mask rpcbind.socket rpcbind.service
fi
printf " •${YELLOW} Ensure rpcbind services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s tftpd-hpa &>/dev/null; then
    systemctl stop tftpd-hpa.service
    apt purge -y tftpd-hpa
elif systemctl is-enabled tftpd-hpa.service 2>/dev/null | grep -q 'enabled' || \
     systemctl is-active tftpd-hpa.service 2>/dev/null | grep -q '^active'; then
    systemctl stop tftpd-hpa.service
    systemctl mask tftpd-hpa.service
fi
printf " •${YELLOW} Ensure tftp server services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s squid &>/dev/null; then
    systemctl stop squid.service
    apt purge -y squid
elif systemctl is-enabled squid.service 2>/dev/null | grep -q 'enabled' || \
     systemctl is-active squid.service 2>/dev/null | grep -q '^active'; then
    systemctl stop squid.service
    systemctl mask squid.service
fi
printf " •${YELLOW} Ensure web proxy server services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s nfs-kernel-server &>/dev/null; then
    systemctl stop nfs-server.service
    apt purge -y nfs-kernel-server
elif systemctl is-enabled nfs-server.service 2>/dev/null | grep -q 'enabled' || \
     systemctl is-active nfs-server.service 2>/dev/null | grep -q '^active'; then
    systemctl stop nfs-server.service
    systemctl mask nfs-server.service
fi
printf " •${YELLOW} Ensure network file system services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
echo -e "➽ ${GREEN}Configuring server services completed${RESET}"
sleep 5

printf "${BLUE}[+] Services${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring Client Services${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

if dpkg-query -s nis &>/dev/null; then
    apt purge -y nis
fi
printf " •${YELLOW} Ensure NIS Client is not installed...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s rsh-client &>/dev/null; then
    apt purge -y rsh-client
fi
printf " •${YELLOW} Ensure rsh client is not installed...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s talk &>/dev/null; then
    apt purge -y talk
fi
printf " •${YELLOW} Ensure talk client is not installed...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -l | grep -E 'telnet|inetutils-telnet' &>/dev/null; then
    apt purge -y telnet
    apt purge -y inetutils-telnet
fi
printf " •${YELLOW} Uninstalling telnet client...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -s ldap-utils &>/dev/null; then
    apt purge -y ldap-utils
fi
printf " •${YELLOW} Uninstalling ldap client...${RESET}[${GREEN}DONE${RESET}]\n"
if dpkg-query -l | grep -E 'ftp|tnftp' &>/dev/null; then
    apt purge -y ftp
    apt purge -y tnftp
fi
printf " •${YELLOW} Uninstalling ftp & tnftp clients...${RESET}[${GREEN}DONE${RESET}]\n"
echo -e "➽ ${GREEN}Configuring client services completed${RESET}"
sleep 5

printf "${BLUE}[+] Services${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring Time Synchronization${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

apt install -y chrony &>/dev/null
systemctl stop systemd-timesyncd.service &>/dev/null
systemctl mask systemd-timesyncd.service &>/dev/null
printf " •${YELLOW} Ensure a single time synchronization daemon is in use (Chrony)...${RESET}[${GREEN}DONE${RESET}]\n"
if [ ! -d "/etc/chrony/sources.d/" ]; then
    mkdir /etc/chrony/sources.d/
fi
echo -e "# NIST time servers\nserver time-a-g.nist.gov iburst\nserver 132.163.97.3 iburst\nserver time-d-b.nist.gov iburst" > /etc/chrony/sources.d/60-sources.sources
if ! grep -q "^sourcedir /etc/chrony/sources.d" /etc/chrony/chrony.conf; then
    echo "sourcedir /etc/chrony/sources.d" >> /etc/chrony/chrony.conf
fi
systemctl reload-or-restart chronyd &>/dev/null
printf " •${YELLOW} Configuring Chrony with authorized timeservers...${RESET}[${GREEN}DONE${RESET}]\n"
if ps -ef | awk '(/[c]hronyd/ && $1=="_chrony") { exit 0 }'; then
    printf " •${YELLOW} Ensure chrony is running as user _chrony...${RESET}[${GREEN}DONE${RESET}]\n"
else
    echo "user _chrony" >> /etc/chrony/chrony.conf
    systemctl restart chronyd &>/dev/null
    printf " •${YELLOW} Ensure chrony is running as user _chrony...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if systemctl is-enabled chrony.service &>/dev/null && systemctl is-active chrony.service &>/dev/null; then
    Printf " •${YELLOW} Ensure chrony is enabled and running...${RESET}[${GREEN}DONE${RESET}]\n"
else
    systemctl unmask chrony.service &>/dev/null
    systemctl --now enable chrony.service &>/dev/null
    printf " •${YELLOW} Ensure chrony is enabled and running...${RESET}[${GREEN}DONE${RESET}]\n"
fi
echo -e "➽ ${GREEN}Configuring time Synchronization completed${RESET}"
sleep 5

printf "${BLUE}[+] Services${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring job schedulers${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

cron_service=$(systemctl list-unit-files | awk '$1~/^crond?\.service/{print $1}')

if systemctl is-enabled "$cron_service" &>/dev/null && systemctl is-active "$cron_service" &>/dev/null; then
    printf " •${YELLOW} Ensure cron daemon is enabled and active...${RESET}[${GREEN}DONE${RESET}]\n"
else
    systemctl unmask "$cron_service" &>/dev/null
    systemctl --now enable "$cron_service" &>/dev/null
    printf " •${YELLOW} Ensure cron daemon is enabled and active...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if [ -f /etc/crontab ]; then
    perms=$(stat -Lc '%a' /etc/crontab)
    owner=$(stat -Lc '%u' /etc/crontab)
    group=$(stat -Lc '%g' /etc/crontab)

    if [[ "$perms" == "600" && "$owner" == "0" && "$group" == "0" ]]; then
        printf " •${YELLOW} Ensure permissions on /etc/crontab are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        chown root:root /etc/crontab
        chmod og-rwx /etc/crontab
        printf " •${YELLOW} Ensure permissions on /etc/crontab are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
else
    echo -e " • /etc/crontab file does not exist, skipping remediation...[${YELLOW}SKIP${RESET}]\n"
fi
if [ -d /etc/cron.hourly ]; then
    perms=$(stat -Lc '%a' /etc/cron.hourly)
    owner=$(stat -Lc '%u' /etc/cron.hourly)
    group=$(stat -Lc '%g' /etc/cron.hourly)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        printf " •${YELLOW} Ensure permissions on /etc/cron.hourly are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        chown root:root /etc/cron.hourly
        chmod og-rwx /etc/cron.hourly
        printf " •${YELLOW} Ensure permissions on /etc/cron.hourly are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
else
    echo -e " • /etc/cron.hourly directory does not exist, skipping remediation...[${YELLOW}SKIP${RESET}]\n"
fi
if [ -d /etc/cron.daily ]; then
    perms=$(stat -Lc '%a' /etc/cron.daily)
    owner=$(stat -Lc '%u' /etc/cron.daily)
    group=$(stat -Lc '%g' /etc/cron.daily)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        printf " •${YELLOW} Ensure permissions on /etc/cron.daily are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        chown root:root /etc/cron.daily
        chmod og-rwx /etc/cron.daily
        printf " •${YELLOW} Ensure permissions on /etc/cron.daily are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
else
    echo -e " • /etc/cron.daily directory does not exist, skipping remediation...[${YELLOW}SKIP${RESET}]\n"
fi
if [ -d /etc/cron.weekly ]; then
    perms=$(stat -Lc '%a' /etc/cron.weekly)
    owner=$(stat -Lc '%u' /etc/cron.weekly)
    group=$(stat -Lc '%g' /etc/cron.weekly)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        printf " •${YELLOW} Ensure permissions on /etc/cron.weekly are configuredy...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        chown root:root /etc/cron.weekly
        chmod og-rwx /etc/cron.weekly
        printf " •${YELLOW} Ensure permissions on /etc/cron.weekly are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
else
    echo -e " • /etc/cron.weekly directory does not exist, skipping remediation...[${YELLOW}SKIP${RESET}]\n"
fi
if [ -d /etc/cron.monthly ]; then
    perms=$(stat -Lc '%a' /etc/cron.monthly)
    owner=$(stat -Lc '%u' /etc/cron.monthly)
    group=$(stat -Lc '%g' /etc/cron.monthly)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        printf " •${YELLOW} Ensure permissions on /etc/cron.monthly are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        chown root:root /etc/cron.monthly
        chmod og-rwx /etc/cron.monthly
        printf " •${YELLOW} Ensure permissions on /etc/cron.monthly are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
else
    echo -e " • /etc/cron.monthly directory does not exist, skipping remediation...[${YELLOW}SKIP${RESET}]\n"
fi
if [ -d /etc/cron.d ]; then
    perms=$(stat -Lc '%a' /etc/cron.d)
    owner=$(stat -Lc '%u' /etc/cron.d)
    group=$(stat -Lc '%g' /etc/cron.d)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        printf " •${YELLOW} Ensure permissions on /etc/cron.d are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        chown root:root /etc/cron.d
        chmod og-rwx /etc/cron.d
        printf " •${YELLOW} Ensure permissions on /etc/cron.d are configured...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
else
    echo -e " • /etc/cron.d directory does not exist, skipping remediation...[${YELLOW}SKIP${RESET}]\n"
fi

if [ ! -e "/etc/cron.allow" ]; then
    touch /etc/cron.allow
fi

chmod 640 /etc/cron.allow
if grep -Pq -- '^\h*crontab\:' /etc/group; then
    chown root:crontab /etc/cron.allow
else
    chown root:root /etc/cron.allow
fi
printf " •${YELLOW} Ensure /etc/cron.allow configured...${RESET}[${GREEN}DONE${RESET}]\n"

if [ -e "/etc/cron.deny" ]; then
    chmod 640 /etc/cron.deny
    if grep -Pq -- '^\h*crontab\:' /etc/group; then
        chown root:crontab /etc/cron.deny
    else
        chown root:root /etc/cron.deny
    fi
    printf " •${YELLOW} Ensure /etc/cron.deny configured...${RESET}[${GREEN}DONE${RESET}]\n"
else
   printf " •${YELLOW} Ensure /etc/cron.deny does not exist. No changes needed...${RESET}[${GREEN}SKIPPING${RESET}]\n"
fi

if grep -Pq -- '^daemon\b' /etc/group; then
    AT_GROUP="daemon"
else
    AT_GROUP="root"
fi

if [ ! -e "/etc/at.allow" ]; then
    touch /etc/at.allow
    echo -e " /etc/at.allow created...[${GREEN}DONE${RESET}]\n"
fi

chown root:$AT_GROUP /etc/at.allow
chmod 640 /etc/at.allow
printf " •${YELLOW} Ensure /etc/at.allow permissions set to 640, owner root:$AT_GROUP...${RESET}[${GREEN}DONE${RESET}]\n"

if [ -e "/etc/at.deny" ]; then
    chown root:$AT_GROUP /etc/at.deny
    chmod 640 /etc/at.deny
    printf " •${YELLOW} Ensure /etc/at.deny permissions set to 640, owner root:$AT_GROUP...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure /etc/at.deny does not exist, no changes needed...${RESET}[${GREEN}SKIPPING${RESET}]\n"
fi
echo -e "➽ ${GREEN}Configuring job schedulers completed${RESET}"
sleep 5

printf "${BLUE}[+] Network${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring Network Devices${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

ipv6_status=$(sysctl -n net.ipv6.conf.all.disable_ipv6)
ipv6_default_status=$(sysctl -n net.ipv6.conf.default.disable_ipv6)
if [ "$ipv6_status" -eq 1 ] || [ "$ipv6_default_status" -eq 1 ]; then
    echo "Enabling IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=0
    sysctl -w net.ipv6.conf.default.disable_ipv6=0
    printf " •${YELLOW} IPv6 enabled...${RESET}[${GREEN}DONE${RESET}]\n"
    echo "net.ipv6.conf.all.disable_ipv6=0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6=0" >> /etc/sysctl.conf
    sysctl -p
    printf " •${YELLOW} IPv6 configuration done...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} IPv6 is already enabled and configured...${RESET}[${GREEN}SKIPPED${RESET}]\n"
fi
if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
    read -p "Do you want to disable wireless interfaces? (Yy/Nn): " user_input
    if [[ "$user_input" =~ ^[Yy]$ ]]; then
        module_fix() {
            if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
                echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
            fi
            if lsmod | grep "$l_mname" > /dev/null 2>&1; then
                modprobe -r "$l_mname"
            fi
            if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
                echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
            fi
        }

        l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)"; done | sort -u)
        for l_mname in $l_dname; do
            module_fix
        done
        printf " •${YELLOW} Ensure wireless interfaces are disabled...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        printf " •${YELLOW} Ensure wireless interfaces are disabled...${RESET}[${RED}SKIPPED${RESET}]\n"
    fi
else
    printf " •${YELLOW} No wireless interfaces found...${RESET}[${GREEN}SKIPPED${RESET}]\n"
fi

if dpkg-query -s bluez &>/dev/null; then
    systemctl stop bluetooth.service
    apt purge -y bluez
    printf " •${YELLOW} Ensure bluetooth services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
else
    if systemctl is-active bluetooth.service 2>/dev/null | grep -q '^active'; then
        systemctl stop bluetooth.service
        systemctl mask bluetooth.service
        printf " •${YELLOW} Ensure bluetooth services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        printf " •${YELLOW} Ensure bluetooth services are not in use...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
fi
echo -e "➽ ${GREEN}Configuring network devices completed${RESET}"
sleep 5

printf "${BLUE}[+] Network${RESET}\n"
printf "╭───────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring Network kernel modules${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────────╯\n"
sleep 5

l_mod_name="dccp"
lsmod | grep -q "^$l_mod_name" && modprobe -r "$l_mod_name" 2>/dev/null
echo "install $l_mod_name /bin/false" > /etc/modprobe.d/"$l_mod_name".conf
echo "blacklist $l_mod_name" >> /etc/modprobe.d/"$l_mod_name".conf
printf " •${YELLOW} Ensure dccp kernel module is not available...${RESET}[${GREEN}DONE${RESET}]\n"

l_mod_name="tipc"
lsmod | grep -q "^$l_mod_name" && modprobe -r "$l_mod_name" 2>/dev/null
echo "install $l_mod_name /bin/false" > /etc/modprobe.d/"$l_mod_name".conf
echo "blacklist $l_mod_name" >> /etc/modprobe.d/"$l_mod_name".conf
update-initramfs -u >/dev/null 2>&1
printf " •${YELLOW} Ensure TIPC kernel module is not available...${RESET}[${GREEN}DONE${RESET}]\n"

l_mod_name="rds"
lsmod | grep -q "^$l_mod_name" && modprobe -r "$l_mod_name" 2>/dev/null
echo "install $l_mod_name /bin/false" > /etc/modprobe.d/"$l_mod_name".conf
echo "blacklist $l_mod_name" >> /etc/modprobe.d/"$l_mod_name".conf
update-initramfs -u >/dev/null 2>&1
printf " •${YELLOW} Ensure rds kernel module is not available...${RESET}[${GREEN}DONE${RESET}]\n"

l_mod_name="sctp"
lsmod | grep -q "^$l_mod_name" && modprobe -r "$l_mod_name" 2>/dev/null
echo "install $l_mod_name /bin/false" > /etc/modprobe.d/"$l_mod_name".conf
echo "blacklist $l_mod_name" >> /etc/modprobe.d/"$l_mod_name".conf
update-initramfs -u >/dev/null 2>&1
printf " •${YELLOW} Ensure sctp kernel module is not available...${RESET}[${GREEN}DONE${RESET}]\n"
echo -e "➽ ${GREEN}Configuring network kernel module completed${RESET}"
sleep 5

printf "${BLUE}[+] Network${RESET}\n"
printf "╭───────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring Network kernel parameters${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────────╯\n"
sleep 5

sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1
sysctl -w net.ipv6.conf.all.forwarding=0 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1
sysctl -w net.ipv6.route.flush=1 > /dev/null 2>&1
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf 2>/dev/null
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf 2>/dev/null
sysctl --system > /dev/null 2>&1
printf " •${YELLOW} Ensure ip forwarding is disabled...${RESET}[${GREEN}DONE${RESET}]\n"

sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv4.conf.default.send_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf 2>/dev/null
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf 2>/dev/null
sysctl --system > /dev/null 2>&1
printf " •${YELLOW} Ensure packet redirect sending is disabled...${RESET}[${GREEN}DONE${RESET}]\n"

sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf 2>/dev/null
sysctl --system > /dev/null 2>&1
printf " •${YELLOW} Ensure bogus ICMP responses are ignored...${RESET}[${GREEN}DONE${RESET}]\n"

config_file="/etc/sysctl.d/60-netipv4_sysctl.conf"
sed -i '/^net.ipv4.icmp_echo_ignore_broadcasts/d' "$config_file"
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> "$config_file"
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1
sysctl --system >/dev/null 2>&1
printf " •${YELLOW} Ensure broadcast icmp requests are ignored...${RESET}[${GREEN}DONE${RESET}]\n"

sysctl -w net.ipv4.conf.all.accept_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv4.conf.default.accept_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.all.accept_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv6.conf.default.accept_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv6.route.flush=1 > /dev/null 2>&1
printf " •${YELLOW} Ensure icmp redirects are not accepted...${RESET}[${GREEN}DONE${RESET}]\n"

echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv4.conf.default.secure_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1
printf " •${YELLOW} Ensure secure icmp redirects are not accepted...${RESET}[${GREEN}DONE${RESET}]\n"

echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.rp_filter=1 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1
printf " •${YELLOW} Ensure reverse path filtering is enabled...${RESET}[${GREEN}DONE${RESET}]\n"

sysctl -w net.ipv4.conf.all.accept_source_route=0 &>/dev/null
sysctl -w net.ipv4.conf.default.accept_source_route=0 &>/dev/null
sysctl -w net.ipv4.route.flush=1 &>/dev/null
sysctl -w net.ipv6.conf.all.accept_source_route=0 &>/dev/null
sysctl -w net.ipv6.conf.default.accept_source_route=0 &>/dev/null
sysctl -w net.ipv6.route.flush=1 &>/dev/null
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
sysctl -p &>/dev/null
printf " •${YELLOW} Ensure source routed packets are not accepted...${RESET}[${GREEN}DONE${RESET}]\n"

ufw_sysctl_conf="/etc/ufw/sysctl.conf"
param1="net.ipv4.conf.all.log_martians=1"
param2="net.ipv4.conf.default.log_martians=1"
grep -q "$param1" "$ufw_sysctl_conf" || echo "$param1" | sudo tee -a "$ufw_sysctl_conf" > /dev/null
grep -q "$param2" "$ufw_sysctl_conf" || echo "$param2" | sudo tee -a "$ufw_sysctl_conf" > /dev/null
sudo sysctl -p /etc/ufw/sysctl.conf > /dev/null
sudo sysctl -w net.ipv4.conf.all.log_martians=1 > /dev/null
sudo sysctl -w net.ipv4.conf.default.log_martians=1 > /dev/null
sudo sysctl -w net.ipv4.route.flush=1 > /dev/null
printf " •${YELLOW} Ensure suspicious packets are logged...${RESET}[${GREEN}DONE${RESET}]\n"

sysctl_conf="/etc/sysctl.d/60-netipv4_sysctl.conf"
param="net.ipv4.tcp_syncookies=1"
grep -q "$param" "$sysctl_conf" || echo "$param" | sudo tee -a "$sysctl_conf" > /dev/null
sudo sysctl -p /etc/sysctl.d/60-netipv4_sysctl.conf > /dev/null
sudo sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null
sudo sysctl -w net.ipv4.route.flush=1 > /dev/null
printf " •${YELLOW} Ensure TCP SYN cookies are enabled...${RESET}[${GREEN}DONE${RESET}]\n"

sysctl_conf="/etc/sysctl.d/60-netipv6_sysctl.conf"
param1="net.ipv6.conf.all.accept_ra=0"
param2="net.ipv6.conf.default.accept_ra=0"
grep -q "$param1" "$sysctl_conf" || echo "$param1" | sudo tee -a "$sysctl_conf" > /dev/null
grep -q "$param2" "$sysctl_conf" || echo "$param2" | sudo tee -a "$sysctl_conf" > /dev/null
sudo sysctl -p "$sysctl_conf" > /dev/null
sudo sysctl -w net.ipv6.conf.all.accept_ra=0 > /dev/null
sudo sysctl -w net.ipv6.conf.default.accept_ra=0 > /dev/null
printf " •${YELLOW} Ensure IPv6 Router Advertisements are not accepted...${RESET}[${GREEN}DONE${RESET}]\n"
echo -e "➽ ${GREEN}Configuring network kernel parameters completed${RESET}"
sleep 5

printf "${BLUE}[+] Host Based Firewall${RESET}\n"
printf "╭───────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring single firewall utility${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────────╯\n"
sleep 5

firewalls=("ufw" "nftables" "iptables")
active_firewalls=()
for firewall in "${firewalls[@]}"; do
    case $firewall in
        nftables) cmd="nft" ;;
        *) cmd=$firewall ;;
    esac
    
    if command -v $cmd &> /dev/null && systemctl is-enabled --quiet $firewall && systemctl is-active --quiet $firewall; then
        active_firewalls+=("$firewall")
    fi
done
if [ ${#active_firewalls[@]} -gt 1 ]; then
    read -rp "Do you want to change to a single firewall? (Yy/Nn): " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "Select the firewall to keep:"
        echo "1) ufw"
        echo "2) nftables"
        echo "3) iptables"
        read -rp "Enter choice (1/2/3): " choice
        
        case $choice in
            1) selected="ufw" ;;
            2) selected="nftables" ;;
            3) selected="iptables" ;;
            *) echo "Invalid choice. Exiting."; exit 1 ;;
        esac
        for fw in "${active_firewalls[@]}"; do
            if [[ "$fw" != "$selected" ]]; then
                echo "Disabling $fw..."
                systemctl stop "$fw"
                systemctl disable "$fw"
            fi
        done
        echo "Enabling $selected..."
        systemctl enable "$selected"
        systemctl start "$selected"
        printf " •${YELLOW} Ensure a single firewall configuration utility is in use...${RESET} Now only [$selected] is active."
    fi
else
    printf " •${YELLOW} Ensure a single firewall configuration utility is in use...${RESET}[${GREEN}No remediation needed${RESET}]\n"
fi
echo -e "➽ ${GREEN}Configuring single firewall configuration utility completed${RESET}"
sleep 5

printf "${BLUE}[+] Host Based Firewall${RESET}\n"
printf "╭───────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring UncomplicatedFirewall${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────────╯\n"
sleep 5

if dpkg-query -s ufw &>/dev/null; then
    printf " •${YELLOW} Ensure ufw is installed...${RESET}[${GREEN}DONE${RESET}]\n"
else
    echo "Installing UFW..."
    apt update && apt install -y ufw
    printf " •${YELLOW} Ensure ufw is installed...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if dpkg-query -s iptables-persistent &>/dev/null; then
    apt purge -y iptables-persistent &>/dev/null
    printf " •${YELLOW} Ensure iptables-persistent is not installed with ufw...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure iptables-persistent is not installed with ufw...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if systemctl is-enabled --quiet ufw && systemctl is-active --quiet ufw && ufw status | grep -q "Status: active"; then
    printf " •${YELLOW} Ensure ufw service is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
else
    systemctl unmask ufw.service &>/dev/null
    systemctl --now enable ufw.service &>/dev/null
    ufw --force enable &>/dev/null
    printf " •${YELLOW} Ensure ufw service is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if grep -qP 'lo|127.0.0.0' /etc/ufw/before.rules &&
   ufw status verbose | grep -qE 'Anywhere DENY IN 127.0.0.0/8' &&
   ufw status verbose | grep -qE 'Anywhere \(v6\) DENY IN ::1'; then
    printf " •${YELLOW} Ensure ufw loopback traffic is configured...${RESET}[${GREEN}DONE${RESET}]\n"
else
    if ! grep -qP 'lo' /etc/ufw/before.rules; then
        sed -i '/^\*filter/i \
# Allow all traffic on loopback\n-A ufw-before-input -i lo -j ACCEPT\n-A ufw-before-output -o lo -j ACCEPT\n' /etc/ufw/before.rules
    fi

    if ! grep -qE '127.0.0.0/8' /etc/ufw/before.rules; then
        sed -i '/^\*filter/i \
# Deny incoming traffic from loopback addresses on other interfaces\n-A ufw-before-input -s 127.0.0.0/8 -j DROP\n-A ufw-before-input -s ::1 -j DROP\n' /etc/ufw/before.rules
    fi
    ufw allow in on lo &>/dev/null
    ufw allow out on lo &>/dev/null
    ufw deny in from 127.0.0.0/8 &>/dev/null
    ufw deny in from ::1 &>/dev/null
    cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
    ed -i '0,/\*filter/s/^/#/' /etc/ufw/before.rules
    ufw reload &>/dev/null
    printf " •${YELLOW} Ensure ufw loopback traffic is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! ufw status | grep -q "Status: active"; then
    ufw enable &>/dev/null
fi
if ufw status verbose | grep -qE "Default: deny \(incoming\), allow \(outgoing\)"; then
    printf " •${YELLOW} Ensure ufw outbound connections are configured...${RESET}[${GREEN}DONE${RESET}]\n"
else
    ufw default allow outgoing &>/dev/null
    ufw reload &>/dev/null
    printf " •${YELLOW} Ensure ufw outbound connections are configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
open_ports=$(ufw status verbose | grep -Po '^\h*\d+\b' | sort -u)
system_ports=$(ss -tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/ && $5!~/\[?::1\]?:/) {split($5, a, ":"); print a[2]}' | sort -u)
diff_ports=$(comm -23 <(echo "$system_ports") <(echo "$open_ports"))

if [ -z "$diff_ports" ]; then
    printf " •${YELLOW} Ensure ufw firewall rules exist for all open ports...${RESET}[${GREEN}DONE${RESET}]\n"
else
    while IFS= read -r port; do
        ufw allow $port &>/dev/null
    done <<< "$diff_ports"
    ufw reload &>/dev/null
    printf " •${YELLOW} Ensure ufw firewall rules exist for all open ports...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ufw status verbose | grep -qE "Default: deny \(incoming\), deny \(outgoing\), disabled \(routed\)"; then
    printf " •${YELLOW} Ensure ufw default deny firewall policy...${RESET}[${GREEN}DONE${RESET}]\n"
else
    ufw default deny incoming &>/dev/null
    ufw default deny outgoing &>/dev/null
    ufw default deny routed &>/dev/null
    sudo ufw delete deny in from 127.0.0.0/8
    sudo ufw delete deny in from ::1
    ufw reload &>/dev/null
    printf " •${YELLOW} Ensure ufw default deny firewall policy...${RESET}[${GREEN}DONE${RESET}]\n"
fi
echo -e "➽ ${GREEN}Configuring uncomplicatedfirewall completed${RESET}"
sleep 5

printf "${BLUE}[+] Access Control${RESET}\n"
printf "╭───────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring ssh server${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────────╯\n"
sleep 5

fixed=0
for file in /etc/ssh/sshd_config $(find /etc/ssh/sshd_config.d -type f -name '*.conf' 2>/dev/null); do
    [ -e "$file" ] || continue
    if [ "$(stat -c '%a' "$file")" -gt 600 ] || [ "$(stat -c '%U' "$file")" != "root" ] || [ "$(stat -c '%G' "$file")" != "root" ]; then
        chmod 600 "$file"
        chown root:root "$file"
        fixed=1
    fi
done
if [ "$fixed" -eq 1 ]; then
    printf " •${YELLOW} Ensure permissions on SSH config files...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure permissions on SSH config files...${RESET}[${GREEN}DONE${RESET}]\n"
fi

ssh_group_name=$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)
for file in $(find /etc/ssh -type f -name '*_key' 2>/dev/null); do
    if ssh-keygen -lf &>/dev/null "$file"; then
        file_mode=$(stat -c '%a' "$file")
        file_owner=$(stat -c '%U' "$file")
        file_group=$(stat -c '%G' "$file")
        if [ "$file_owner" != "root" ]; then
            chown root "$file"
        fi
        if [[ ! "$file_group" =~ $ssh_group_name|root ]]; then
            chgrp "$ssh_group_name" "$file" || chgrp root "$file"
        fi
        if [ "$file_mode" -gt 640 ]; then
            chmod 640 "$file"
        fi
    fi
done
printf " •${YELLOW} Ensure permissions on SSH private host key files...${RESET}[${GREEN}DONE${RESET}]\n"

ssh_group_name=$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)
l_pmask="0133"
l_maxperm="$(printf '%o' $((0777 & ~$l_pmask)))"
for file in $(find /etc/ssh -type f -name '*_key.pub' 2>/dev/null); do
    file_mode=$(stat -c '%a' "$file")
    file_owner=$(stat -c '%U' "$file")
    file_group=$(stat -c '%G' "$file")
    if [ $((file_mode & $l_pmask)) -gt 0 ]; then
        chmod u-x,go-wx "$file"
    fi
    if [ "$file_owner" != "root" ]; then
        chown root "$file"
    fi
    if [ "$file_group" != "root" ]; then
        chgrp root "$file"
    fi
done
printf " •${YELLOW} Ensure permissions on SSH public host key files...${RESET}[${GREEN}DONE${RESET}]\n"
ALLOW_USERS="<userlist>"
ALLOW_GROUPS="<grouplist>"
if ! grep -qE "^AllowUsers" /etc/ssh/sshd_config; then
    echo "AllowUsers $ALLOW_USERS" >> /etc/ssh/sshd_config
fi
if ! grep -qE "^AllowGroups" /etc/ssh/sshd_config; then
    echo "AllowGroups $ALLOW_GROUPS" >> /etc/ssh/sshd_config
fi
systemctl restart sshd
printf " •${YELLOW} Ensure sshd access is configured...${RESET}[${GREEN}DONE${RESET}]\n"
BANNER_PATH="/etc/issue.net"
if ! grep -qE "^Banner" /etc/ssh/sshd_config; then
    echo "Banner $BANNER_PATH" >> /etc/ssh/sshd_config
fi
echo "Authorized users only. All activity may be monitored and reported." > "$BANNER_PATH"
systemctl restart ssh || echo "Failed to restart SSH service."
printf " •${YELLOW} Ensure sshd Banner is configured...${RESET}[${GREEN}DONE${RESET}]\n"

if ! grep -q '^Ciphers' /etc/ssh/sshd_config; then
    echo "Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com" | sudo tee -a /etc/ssh/sshd_config > /dev/null
else
    sudo sed -i 's/^Ciphers.*/Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com/' /etc/ssh/sshd_config
fi
sudo systemctl restart ssh.service
ciphers_set=$(sshd -T | grep '^ciphers')
if [[ "$ciphers_set" == *"3des-cbc"* || "$ciphers_set" == *"aes128-cbc"* || "$ciphers_set" == *"aes192-cbc"* || "$ciphers_set" == *"aes256-cbc"* || "$ciphers_set" == *"chacha20-poly1305@openssh.com"* ]]; then
    printf " •${YELLOW} Ensure sshd Ciphers are configured...${RESET}[${RED}FAIL${RESET}] - Weak ciphers still present"
else
    printf " •${YELLOW} Ensure sshd Ciphers are configured...${RESET}[${GREEN}DONE${RESET}]"
fi
required_interval=15
required_countmax=3
sudo sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config
sudo sed -i '/^ClientAliveCountMax/d' /etc/ssh/sshd_config
echo "ClientAliveInterval $required_interval" | sudo tee -a /etc/ssh/sshd_config > /dev/null
echo "ClientAliveCountMax $required_countmax" | sudo tee -a /etc/ssh/sshd_config > /dev/null
sudo systemctl restart ssh.service
updated_interval=$(sshd -T | grep -i '^clientaliveinterval' | awk '{print $2}')
updated_countmax=$(sshd -T | grep -i '^clientalivecountmax' | awk '{print $2}')
if [[ "$updated_interval" -eq "$required_interval" && "$updated_countmax" -eq "$required_countmax" ]]; then
    printf " •${YELLOW} Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured...${RESET}[${GREEN}DONE${RESET}]"
fi
required_value="yes"
sudo sed -i '/^DisableForwarding/d' /etc/ssh/sshd_config
echo "DisableForwarding $required_value" | sudo tee -a /etc/ssh/sshd_config > /dev/null
sudo systemctl restart ssh.service
updated_value=$(sshd -T | grep -i '^disableforwarding' | awk '{print $2}')
if [[ "$updated_value" == "$required_value" ]]; then
    printf " •${YELLOW} Ensure sshd DisableForwarding is enabled...${RESET}[${GREEN}DONE${RESET}]"
fi
required_value="no"
sudo sed -i '/^GSSAPIAuthentication/d' /etc/ssh/sshd_config
echo "GSSAPIAuthentication $required_value" | sudo tee -a /etc/ssh/sshd_config > /dev/null
sudo systemctl restart ssh.service
updated_value=$(sshd -T | grep -i '^gssapiauthentication' | awk '{print $2}')
if [[ "$updated_value" == "$required_value" ]]; then
    printf " •${YELLOW} Ensure sshd GSSAPIAuthentication is disabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
required_value="no"
sudo sed -i '/^HostbasedAuthentication/d' /etc/ssh/sshd_config
echo "HostbasedAuthentication $required_value" | sudo tee -a /etc/ssh/sshd_config > /dev/null
sudo systemctl restart ssh.service
updated_value=$(sshd -T | grep -i '^hostbasedauthentication' | awk '{print $2}')
if [[ "$updated_value" == "$required_value" ]]; then
    printf " •${YELLOW} Ensure sshd HostbasedAuthentication is disabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
required_value="yes"
sudo sed -i '/^IgnoreRhosts/d' /etc/ssh/sshd_config
echo "IgnoreRhosts $required_value" | sudo tee -a /etc/ssh/sshd_config > /dev/null
sudo systemctl restart ssh.service
updated_value=$(sshd -T | grep -i '^ignorerhosts' | awk '{print $2}')
if [[ "$updated_value" == "$required_value" ]]; then
    printf " •${YELLOW} Ensure sshd IgnoreRhosts is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
required_algorithms="sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"
sudo sed -i '/^KexAlgorithms/d' /etc/ssh/sshd_config
echo "KexAlgorithms $required_algorithms" | sudo tee -a /etc/ssh/sshd_config > /dev/null
sudo systemctl restart ssh.service
updated_algorithms=$(sshd -T | grep -i '^kexalgorithms' | awk '{print $2}')
if [[ "$updated_algorithms" == "$required_algorithms" ]]; then
    printf " •${YELLOW} Ensure sshd KexAlgorithms is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
login_grace_time="60"
sudo sed -i '/^LoginGraceTime/d' /etc/ssh/sshd_config
sudo awk -v new_line="LoginGraceTime $login_grace_time" '
    BEGIN { added = 0 }
    /^Include/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
updated_grace_time=$(sshd -T | grep -i '^logingracetime' | awk '{print $2}')
if [[ "$updated_grace_time" == "$login_grace_time" ]]; then
    printf " •${YELLOW} Ensure sshd LoginGraceTime is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
desired_log_level="VERBOSE"
sudo sed -i '/^LogLevel/d' /etc/ssh/sshd_config
sudo awk -v new_line="LogLevel $desired_log_level" '
    BEGIN { added = 0 }
    /^Include|^Match/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
updated_log_level=$(sshd -T | grep -i '^loglevel' | awk '{print $2}')
if [[ "$updated_log_level" == "$desired_log_level" ]]; then
    printf " •${YELLOW} Ensure sshd LogLevel is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
excluded_macs="-hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com"
sudo sed -i '/^MACs/d' /etc/ssh/sshd_config
sudo awk -v new_line="MACs $excluded_macs" '
    BEGIN { added = 0 }
    /^Include|^Match/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
verify_weak_macs=$(sshd -T | grep -Pi -- 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b')
if [[ -z "$verify_weak_macs" ]]; then
    printf " •${YELLOW} Ensure sshd MACs are configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
max_auth_tries="4"
sudo sed -i '/^MaxAuthTries/d' /etc/ssh/sshd_config
sudo awk -v new_line="MaxAuthTries $max_auth_tries" '
    BEGIN { added = 0 }
    /^Include|^Match/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
updated_max_auth_tries=$(sshd -T | grep -i '^maxauthtries' | awk '{print $2}')
if [[ "$updated_max_auth_tries" == "$max_auth_tries" ]]; then
    printf " •${YELLOW} Ensure sshd MaxAuthTries is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
max_sessions="10"
sudo sed -i '/^MaxSessions/d' /etc/ssh/sshd_config
sudo awk -v new_line="MaxSessions $max_sessions" '
    BEGIN { added = 0 }
    /^Include|^Match/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
updated_max_sessions=$(sshd -T | grep -i '^maxsessions' | awk '{print $2}')
if [[ "$updated_max_sessions" == "$max_sessions" ]]; then
    printf " •${YELLOW} Ensure sshd MaxSessions is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
max_startups="10:30:60"
sudo sed -i '/^MaxStartups/d' /etc/ssh/sshd_config
sudo awk -v new_line="MaxStartups $max_startups" '
    BEGIN { added = 0 }
    /^Include|^Match/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
updated_max_startups=$(sshd -T | grep -i '^maxstartups' | awk '{print $2}')
if [[ "$updated_max_startups" == "$max_startups" ]]; then
    printf " •${YELLOW} Ensure sshd MaxStartups is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
sudo sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config
sudo awk -v new_line="PermitEmptyPasswords no" '
    BEGIN { added = 0 }
    /^Include|^Match/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
permit_empty_updated=$(sshd -T | grep -i '^permitemptypasswords' | awk '{print $2}')
if [[ "$permit_empty_updated" == "no" ]]; then
    printf " •${YELLOW} Ensure sshd PermitEmptyPasswords is disabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
sudo sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config
sudo awk -v new_line="PermitRootLogin no" '
    BEGIN { added = 0 }
    /^Include|^Match/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
permit_root_updated=$(sshd -T | grep -i '^permitrootlogin' | awk '{print $2}')
if [[ "$permit_root_updated" == "no" ]]; then
    printf " •${YELLOW} Ensure sshd PermitRootLogin is disabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
sudo sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config
sudo awk -v new_line="PermitUserEnvironment no" '
    BEGIN { added = 0 }
    /^Include|^Match/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
permit_env_updated=$(sshd -T | grep -i '^permituserenvironment' | awk '{print $2}')
if [[ "$permit_env_updated" == "no" ]]; then
    printf " •${YELLOW} Ensure sshd PermitUserEnvironment is disabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
sudo sed -i '/^UsePAM/d' /etc/ssh/sshd_config
sudo awk -v new_line="UsePAM yes" '
    BEGIN { added = 0 }
    /^Include|^Match/ && !added { print new_line; added = 1 }
    { print }
    END { if (!added) print new_line }
' /etc/ssh/sshd_config > /tmp/sshd_config.tmp && sudo mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
sudo systemctl restart ssh.service
usepam_updated=$(sshd -T | grep -i '^usepam' | awk '{print $2}')
if [[ "$usepam_updated" == "yes" ]]; then
    printf " •${YELLOW} Ensure sshd UsePAM is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
echo -e "➽ ${GREEN}Configuring ssh server completed${RESET}"
sleep 5
printf "${BLUE}[+] Access Control${RESET}\n"
printf "╭───────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring privilege escalation${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────────╯\n"
sleep 5
if ! dpkg-query -s sudo &>/dev/null && ! dpkg-query -s sudo-ldap &>/dev/null; then
    echo "Installing sudo..."
    sudo apt install -y sudo
    printf " •${YELLOW} Ensure sudo is installed...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure sudo is installed...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! grep -rPi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers /etc/sudoers.d &>/dev/null || \
   grep -rPi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers /etc/sudoers.d &>/dev/null; then
    echo "Configuring sudo to enforce use_pty..."
    if ! grep -qP '^\s*Defaults\s+use_pty\b' /etc/sudoers; then
        echo "Defaults use_pty" | EDITOR='tee -a' visudo >/dev/null
    fi
    for file in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$file" ] && grep -qP '^\s*Defaults\s+([^#\n\r]+,\s*)?!use_pty\b' "$file" && \
        sed -i '/^\s*Defaults\s\+[^#\n\r]*!use_pty\b/d' "$file"
    done
    printf " •${YELLOW} Ensure sudo commands use pty...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure sudo commands use pty...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! grep -rEi '^[[:space:]]*Defaults[[:space:]]+([^#]*,)?[[:space:]]*logfile[[:space:]]*=[[:space:]]*(["'"'"'])?/var/log/sudo\.log(["'"'"'])?(,[[:space:]]*\S+)*[[:space:]]*(#.*)?$' /etc/sudoers /etc/sudoers.d &>/dev/null; then
    echo "Configuring sudo to log to /var/log/sudo.log..."
    if ! grep -qEi '^[[:space:]]*Defaults[[:space:]]+logfile[[:space:]]*=[[:space:]]*["'"'"']?/var/log/sudo\.log["'"'"']?[[:space:]]*$' /etc/sudoers; then
        echo 'Defaults logfile="/var/log/sudo.log"' | sudo EDITOR='tee -a' visudo >/dev/null
    fi
    printf " •${YELLOW} Ensure sudo log file is configured...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure sudo log file is configured...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! grep -rEi '^[[:space:]]*Defaults[[:space:]]+([^#]*,)?[[:space:]]*logfile[[:space:]]*=[[:space:]]*(["'"'"'])?/var/log/sudo\.log(["'"'"'])?(,[[:space:]]*\S+)*[[:space:]]*(#.*)?$' /etc/sudoers /etc/sudoers.d &>/dev/null; then
    if ! grep -qEi '^[[:space:]]*Defaults[[:space:]]+logfile[[:space:]]*=[[:space:]]*["'"'"']?/var/log/sudo\.log["'"'"']?[[:space:]]*$' /etc/sudoers; then
        echo 'Defaults logfile="/var/log/sudo.log"' | sudo EDITOR='tee -a >/dev/null' visudo >/dev/null 2>&1
    fi
fi
printf " •${YELLOW} Ensure sudo log file is configured...${RESET}[${GREEN}DONE${RESET}]\n"
if grep -r "^[^#].*NOPASSWD" /etc/sudoers /etc/sudoers.d &>/dev/null; then
    echo "Removing NOPASSWD entries from sudoers files..."
    for file in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$file" ] && grep -q "^[^#].*NOPASSWD" "$file" && \
        sed -i 's/NOPASSWD://g' "$file"
    done
    printf " •${YELLOW} Ensure sudo requires password for privilege escalation...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure sudo requires password for privilege escalation...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if grep -r "^[^#].*!authenticate" /etc/sudoers /etc/sudoers.d &>/dev/null; then
    echo "Removing '!authenticate' entries from sudoers files..."
    for file in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$file" ] && grep -q "^[^#].*!authenticate" "$file" && \
        sed -i 's/!authenticate//g' "$file"
    done
    printf " •${YELLOW} Ensure re-authentication for privilege escalation is not disabled...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure re-authentication for privilege escalation is not disabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
configured_timeout=$(grep -rP "timestamp_timeout\s*=\s*\K[0-9\-]+" /etc/sudoers /etc/sudoers.d 2>/dev/null | awk -F: '{print $2}' | head -n 1)
if [ -z "$configured_timeout" ] || [ "$configured_timeout" -gt 15 ] 2>/dev/null || [ "$configured_timeout" -eq -1 ] 2>/dev/null; then
    if grep -q "timestamp_timeout=" /etc/sudoers; then
        sed -i 's/timestamp_timeout=[0-9\-]\+/timestamp_timeout=15/' /etc/sudoers
    else
        echo "Defaults timestamp_timeout=15" | EDITOR='tee -a' visudo >/dev/null
    fi
    for file in /etc/sudoers.d/*; do
        [ -f "$file" ] || continue
        if grep -q "timestamp_timeout=" "$file"; then
            sed -i 's/timestamp_timeout=[0-9\-]\+/timestamp_timeout=15/' "$file"
        fi
    done
    printf " •${YELLOW} Ensure sudo authentication timeout is ≤ 15 minutes...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure sudo authentication timeout is ≤ 15 minutes...${RESET}[${GREEN}DONE${RESET}]\n"
fi
SU_GROUP="sugroup"
getent group "$SU_GROUP" &>/dev/null || groupadd "$SU_GROUP"
if ! grep -Piq "^\s*auth\s+(required|requisite)\s+pam_wheel\.so\s+.*use_uid.*group=$SU_GROUP" /etc/pam.d/su; then
    echo "auth required pam_wheel.so use_uid group=$SU_GROUP" >> /etc/pam.d/su
fi
gpasswd -M "" "$SU_GROUP" &>/dev/null
printf " •${YELLOW} Ensure access to the su command is restricted...${RESET}[${GREEN}DONE${RESET}]\n"
echo -e "➽ ${GREEN}Configuring privilage escalation completed${RESET}"
sleep 5
printf "${BLUE}[+] Access Control${RESET}\n"
printf "╭─────────────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring Pluggable Authentication Modules${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────────────╯\n"
sleep 5
required_version="1.5.3-5"
if dpkg-query -s libpam-runtime &>/dev/null; then
    pam_version=$(dpkg-query -W -f='${Version}' libpam-runtime)
    if dpkg --compare-versions "$pam_version" lt "$required_version"; then
        apt update && apt install -y libpam-runtime
        printf " •${YELLOW} Ensure latest version of PAM is installed...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        printf " •${YELLOW} Ensure latest version of PAM is installed...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
else
    apt update && apt install -y libpam-runtime
    printf " •${YELLOW} Ensure latest version of PAM is installed...${RESET}[${GREEN}DONE${RESET}]\n"
fi
required_version="1.5.3-5"
if dpkg-query -s libpam-modules &>/dev/null; then
    pam_mod_version=$(dpkg-query -W -f='${Version}' libpam-modules)
    if dpkg --compare-versions "$pam_mod_version" lt "$required_version"; then
        apt update && apt install -y libpam-modules
        printf " •${YELLOW} Ensure libpam-modules is installed...${RESET}[${GREEN}DONE${RESET}]\n"
    else
        printf " •${YELLOW} Ensure libpam-modules is installed...${RESET}[${GREEN}DONE${RESET}]\n"
    fi
else
    apt update && apt install -y libpam-modules
    printf " •${YELLOW} Ensure libpam-modules is installed...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! dpkg-query -s libpam-pwquality &>/dev/null; then
    apt update && apt install -y libpam-pwquality
    printf " •${YELLOW} Ensure libpam-pwquality is installed...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure libpam-pwquality is installed...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! dpkg-query -s libpam-pwquality &>/dev/null; then
    printf " •${YELLOW} Ensure libpam-pwquality is installed...${RESET}[INSTALLING]\n"
    apt update -qq &>/dev/null
    apt install -y libpam-pwquality &>/dev/null
    tput cuu1 && tput el
fi
printf " •${YELLOW} Ensure libpam-pwquality is installed...${RESET}[${GREEN}DONE${RESET}]\n"
if ! grep -qP '\bpam_unix\.so\b' /etc/pam.d/common-{account,session,auth,password}; then
    pam-auth-update --enable unix
    printf " •${YELLOW} Ensure pam_unix module is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure pam_unix module is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! grep -qP '\bpam_faillock\.so\b' /etc/pam.d/common-auth || ! grep -qP '\bpam_faillock\.so\b' /etc/pam.d/common-account; then
    cat <<EOF > /usr/share/pam-configs/faillock
Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
 [default=die] pam_faillock.so authfail
EOF
    cat <<EOF > /usr/share/pam-configs/faillock_notify
Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
 requisite pam_faillock.so preauth
Account-Type: Primary
Account:
 required pam_faillock.so
EOF
    pam-auth-update --enable faillock
    pam-auth-update --enable faillock_notify
    printf " •${YELLOW} Ensure pam_faillock module is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure pam_faillock module is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! grep -qP '\bpam_pwquality\.so\b' /etc/pam.d/common-password; then
    if ! grep -qP '\bpam_pwquality\.so\b' /usr/share/pam-configs/*; then
        cat <<EOF > /usr/share/pam-configs/pwquality
Name: Pwquality password strength checking
Default: yes
Priority: 1024
Conflicts: cracklib
Password-Type: Primary
Password:
 requisite pam_pwquality.so retry=3
EOF
    fi
    pam-auth-update --enable pwquality
    printf " •${YELLOW} Ensure pam_pwquality module is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure pam_pwquality module is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! grep -qP '\bpam_pwhistory\.so\b' /etc/pam.d/common-password; then
    if ! grep -qP '\bpam_pwhistory\.so\b' /usr/share/pam-configs/*; then
        cat <<EOF > /usr/share/pam-configs/pwhistory
Name: pwhistory password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
 requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok
EOF
    fi
    pam-auth-update --enable pwhistory
    printf " •${YELLOW} Ensure pam_pwhistory module is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Ensure pam_pwhistory module is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
fi
if ! grep -Pq '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf; then
    printf " •${YELLOW} Ensure password lockout deny is set to 5...${RESET}[INSTALLING]\n"

    if grep -q '^\s*deny\s*=' /etc/security/faillock.conf; then
        sed -i 's/^\s*deny\s*=.*/deny = 5/' /etc/security/faillock.conf
    else
        echo "deny = 5" >> /etc/security/faillock.conf
    fi
    tput cuu1 && tput el
    printf " •${YELLOW} Ensure password lockout deny is set to 5...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Password lockout deny setting already compliant...${RESET}[${GREEN}OK${RESET}]\n"
fi
override_files=$(grep -Pl '\bpam_faillock\.so\h+([^#\n\r]+\h+)?deny\b' /usr/share/pam-configs/* 2>/dev/null)
if [ -n "$override_files" ]; then
    printf " •${YELLOW} Checking pam_faillock deny overrides...${RESET}[CLEANING]\n"
    while read -r file; do
        sed -i -E 's/(\bpam_faillock\.so[^\n\r#]*?)\s+deny=\S+/\1/' "$file"
    done <<< "$override_files"
    pam-auth-update --force &>/dev/null
    tput cuu1 && tput el
    printf " •${YELLOW} Checking pam_faillock deny overrides...${RESET}[${GREEN}FIXED${RESET}]\n"
else
    printf " •${YELLOW} Checking pam_faillock deny overrides...${RESET}[${GREEN}OK${RESET}]\n"
fi
printf " •${YELLOW} Ensure password lockout configuration...${RESET}[${GREEN}DONE${RESET}]\n"
if ! grep -Pq '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf; then
    printf " •${YELLOW} Setting unlock_time to 900 in faillock.conf...${RESET}[INSTALLING]\n"

    if grep -q '^\s*unlock_time\s*=' /etc/security/faillock.conf; then
        sed -i 's/^\s*unlock_time\s*=.*/unlock_time = 900/' /etc/security/faillock.conf
    else
        echo "unlock_time = 900" >> /etc/security/faillock.conf
    fi
    tput cuu1 && tput el
    printf " •${YELLOW} Setting unlock_time to 900 in faillock.conf...${RESET}[${GREEN}DONE${RESET}]\n"
else
    printf " •${YELLOW} Password unlock_time already compliant...${RESET}[${GREEN}OK${RESET}]\n"
fi
override_files=$(grep -Pl '\bpam_faillock\.so\h+([^#\n\r]+\h+)?unlock_time\b' /usr/share/pam-configs/* 2>/dev/null)
if [ -n "$override_files" ]; then
    printf " •${YELLOW} Checking pam_faillock unlock_time overrides...${RESET}[CLEANING]\n"
    while read -r file; do
        sed -i -E 's/(\bpam_faillock\.so[^\n\r#]*?)\s+unlock_time=\S+/\1/' "$file"
    done <<< "$override_files"
    pam-auth-update --force &>/dev/null
    tput cuu1 && tput el
    printf " •${YELLOW} Checking pam_faillock unlock_time overrides...${RESET}[${GREEN}FIXED${RESET}]\n"
else
    printf " •${YELLOW} Checking pam_faillock unlock_time overrides...${RESET}[${GREEN}OK${RESET}]\n"
fi
printf " •${YELLOW} Password unlock time configuration complete...${RESET}[${GREEN}DONE${RESET}]\n"
sed -ri 's/^\s*difok\s*=/# &/' /etc/security/pwquality.conf 2>/dev/null
mkdir -p /etc/security/pwquality.conf.d 2>/dev/null
printf '%s\n' "difok = 2" > /etc/security/pwquality.conf.d/50-pwdifok.conf 2>/dev/null
grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?difok\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    sed -i -r 's/(pam_pwquality\.so\s+.*)\bdifok=[0-9]+\b/\1/' "$file" 2>/dev/null
done
printf " •${YELLOW} Ensure password number of changed characters (difok) is configured...${RESET}[${GREEN}DONE${RESET}]\n"
sed -ri 's/^\s*minlen\s*=/# &/' /etc/security/pwquality.conf 2>/dev/null
mkdir -p /etc/security/pwquality.conf.d 2>/dev/null
printf '%s\n' "minlen = 14" > /etc/security/pwquality.conf.d/50-pwlength.conf 2>/dev/null
grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?minlen\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    sed -i -r 's/(pam_pwquality\.so\s+.*)\bminlen=[0-9]+\b/\1/' "$file" 2>/dev/null
done
printf " •${YELLOW} Ensure minimum password length (minlen) is configured...${RESET}[${GREEN}DONE${RESET}]\n"
sed -ri 's/^\s*(minclass|[dulo]credit)\s*=/# &/' /etc/security/pwquality.conf 2>/dev/null
mkdir -p /etc/security/pwquality.conf.d 2>/dev/null
printf '%s\n' \
"minclass = 3" \
"dcredit = -1" \
"ucredit = -1" \
"lcredit = -1" \
"ocredit = -1" > /etc/security/pwquality.conf.d/50-pwcomplexity.conf 2>/dev/null
grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?(minclass|[dulo]credit)\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    sed -i -r 's/(pam_pwquality\.so\s+.*)\b(minclass|[dulo]credit)=-?[0-9]+\b/\1/' "$file" 2>/dev/null
done
printf " •${YELLOW} Ensure password complexity is configured...${RESET}[${GREEN}DONE${RESET}]\n"
sed -ri 's/^\s*maxrepeat\s*=/# &/' /etc/security/pwquality.conf 2>/dev/null
mkdir -p /etc/security/pwquality.conf.d 2>/dev/null
printf '%s\n' "maxrepeat = 3" > /etc/security/pwquality.conf.d/50-pwrepeat.conf 2>/dev/null
grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?maxrepeat\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    sed -i -r 's/(pam_pwquality\.so\s+.*)\bmaxrepeat=[0-9]+\b/\1/' "$file" 2>/dev/null
done
printf " •${YELLOW} Ensure password same consecutive characters (maxrepeat) is configured...${RESET}[${GREEN}DONE${RESET}]\n"
sed -ri 's/^\s*maxsequence\s*=/# &/' /etc/security/pwquality.conf 2>/dev/null
mkdir -p /etc/security/pwquality.conf.d 2>/dev/null
printf '%s\n' "maxsequence = 3" > /etc/security/pwquality.conf.d/50-pwmaxsequence.conf 2>/dev/null
grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?maxsequence\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    sed -i -r 's/(pam_pwquality\.so\s+.*)\bmaxsequence=[0-9]+\b/\1/' "$file" 2>/dev/null
done
printf " •${YELLOW} Ensure password maximum sequential characters (maxsequence) is configured...${RESET}[${GREEN}DONE${RESET}]\n"
sed -ri 's/^\s*dictcheck\s*=/# &/' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null
grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?dictcheck\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    sed -i -r 's/(pam_pwquality\.so\s+.*)\bdictcheck=[0-9]+\b/\1/' "$file" 2>/dev/null
done
printf " •${YELLOW} Ensure password dictionary check (dictcheck) is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
sed -ri 's/^\s*enforcing\s*=\s*0/# &/' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null
grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    sed -i -r 's/(pam_pwquality\.so\s+.*)\benforcing=0\b/\1/' "$file" 2>/dev/null
done
printf " •${YELLOW} Ensure password quality enforcement (enforcing) is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
if [ ! -d /etc/security/pwquality.conf.d/ ]; then
    mkdir -p /etc/security/pwquality.conf.d/
fi
printf '%s\n' "enforce_for_root" > /etc/security/pwquality.conf.d/50-pwroot.conf
printf " •${YELLOW} Ensure password quality enforcement for root is enabled...${RESET}[${GREEN}DONE${RESET}]\n"
pam_file="/etc/pam.d/common-password"
if grep -qP '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so' "$pam_file"; then
    if grep -qP 'remember=\d+' "$pam_file"; then
        sed -ri 's/(pam_pwhistory\.so[^\n\r]*?)remember=\d+/\1remember=24/' "$pam_file"
    else
        sed -ri 's/(pam_pwhistory\.so[^\n\r]*)/\1 remember=24/' "$pam_file"
    fi
else
    printf '%s\n' "password   requisite   pam_pwhistory.so remember=24" >> "$pam_file"
fi
printf " •${YELLOW} Ensure password history remember is configured...${RESET}[${GREEN}DONE${RESET}]\n"
pam_file="/etc/pam.d/common-password"
if grep -qP '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so' "$pam_file"; then
    if ! grep -qP 'pam_pwhistory\.so.*enforce_for_root' "$pam_file"; then
        sed -ri 's/(pam_pwhistory\.so[^\n\r]*)/\1 enforce_for_root/' "$pam_file"
    fi
else
    printf '%s\n' "password   requisite   pam_pwhistory.so remember=24 enforce_for_root" >> "$pam_file"
fi
printf " •${YELLOW} Enforced password history for root user...${RESET}[${GREEN}DONE${RESET}]\n"
pam_file="/etc/pam.d/common-password"
if grep -qP '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so' "$pam_file"; then
    if ! grep -qP 'pam_pwhistory\.so.*use_authtok' "$pam_file"; then
        sed -ri 's/(pam_pwhistory\.so[^\n\r]*)/\1 use_authtok/' "$pam_file"
    fi
else
    printf '%s\n' "password   requisite   pam_pwhistory.so remember=24 enforce_for_root use_authtok" >> "$pam_file"
fi
printf " •${YELLOW} Added use_authtok to pam_pwhistory config...${RESET}[${GREEN}DONE${RESET}]\n"
pam_file="/etc/pam.d/common-password"
if grep -qP '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so' "$pam_file"; then
    if ! grep -qP 'pam_pwhistory\.so.*use_authtok' "$pam_file"; then
        sed -ri 's/(pam_pwhistory\.so[^\n\r]*)/\1 use_authtok/' "$pam_file"
    fi
else
    printf '%s\n' "password   requisite   pam_pwhistory.so remember=24 enforce_for_root use_authtok" >> "$pam_file"
fi
printf " •${YELLOW} Added use_authtok to pam_pwhistory config...${RESET}[${GREEN}DONE${RESET}]\n"
for file in /etc/pam.d/common-{password,auth,account,session,session-noninteractive}; do
    if grep -qP '^\h*[^#\n\r]+\h+pam_unix\.so\b.*\bnullok\b' "$file"; then
        sed -ri 's/\bnullok\b//g; s/\s+/ /g' "$file"
        printf " •${YELLOW} Removed 'nullok' from %s...${RESET}[${GREEN}DONE${RESET}]\n" "$file"
    fi
done
for file in /etc/pam.d/common-{password,auth,account,session,session-noninteractive}; do
    if grep -qP '^\h*[^#\r\n]*pam_unix\.so\b.*\bremember=\d+\b' "$file" 2>/dev/null; then
        sed -ri 's/\bremember=[0-9]+\b//g; s/\s+/ /g' "$file"
        printf " •${YELLOW}Removed 'remember=<N>' from %-50s${RESET}[${GREEN}DONE${RESET}]\n" "$file"
    else
        printf " •${YELLOW}Checked %-60s${RESET}[${BLUE}SKIPPED${RESET}]\n" "$file"
    fi
done
for file in /etc/pam.d/common-password; do
    if grep -qP '^\h*password\h+[^#\r\n]*\h+pam_unix\.so\b(?!.*\b(sha512|yescrypt)\b)' "$file" 2>/dev/null; then
        sed -ri '/^\h*password\h+[^#\r\n]*\h+pam_unix\.so\b/ s/(\bpam_unix\.so\b[^#\r\n]*)/\1 yescrypt/' "$file"
        printf " •${YELLOW}Added strong hash (yescrypt) to %-50s${RESET}[${GREEN}DONE${RESET}]\n" "$file"
    else
        printf " •${YELLOW}Checked %-60s${RESET}[${BLUE}SKIPPED${RESET}]\n" "$file"
    fi
done
for file in /etc/pam.d/common-password; do
    if grep -qP '^\h*password\h+[^#\r\n]*\h+pam_unix\.so\b(?!.*\buse_authtok\b)' "$file" 2>/dev/null; then
        sed -ri '/^\h*password\h+[^#\r\n]*\h+pam_unix\.so\b/ s/(\bpam_unix\.so\b[^#\r\n]*)/\1 use_authtok/' "$file"
        printf " •${YELLOW}Added 'use_authtok' to %-50s${RESET}[${GREEN}DONE${RESET}]\n" "$file"
    else
        printf " •${YELLOW}Checked %-60s${RESET}[${BLUE}SKIPPED${RESET}]\n" "$file"
    fi
done
echo -e "➽ ${GREEN}Configuring Pluggable Authentication Modules completed${RESET}"
sleep 5
printf "${BLUE}[+] User Accounts and Environment ${RESET}\n"
printf "╭─────────────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Configuring shadow password suite parameters ${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────────────╯\n"
sleep 5