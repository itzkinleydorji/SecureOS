#Let's start scripting 
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo:"
  echo "  sudo bash $0"
  exit 1
fi
audit_output=$(mktemp)
exec > >(tee "$audit_output") 2>&1

clear
GREEN='\e[1;32m'
BLUE='\e[1;34m'
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
printf "${CYAN}%*s  GitHub: ${RESET}https://github.com/itzkinleydorji${RESET}\n" "$pad" ""
printf "${CYAN}%*s  Documentation: ${RESET}Plese read on GitHub${RESET}\n" "$pad" ""
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
printf " • ${GREEN}Auditing filesystem kernel modules${RESET}...\n"
printf "╰─..★.──────────────────────────────────────╯\n"
sleep 5
MODPROBE_DIR="/etc/modprobe.d"
BLACKLIST_FILE="$MODPROBE_DIR/blacklist.conf"
MODULE_LIST=("cramfs" "vfat" "exfat" "nfs" "cifs" "gfs2" "fuse" "freevxfs" "hfs" "hfsplus" "jffs2" "overlayfs" "squashfs" "udf" "usb-storage")

if [ ! -f "$BLACKLIST_FILE" ]; then
    touch "$BLACKLIST_FILE"
    echo -e "${GREEN}Created $BLACKLIST_FILE for blacklist configuration.${RESET}"
fi

kernel_module_audit() {
    local module="$1"
    local blacklist_found=false

    if grep -q "^blacklist $module" "$BLACKLIST_FILE"; then
        blacklist_found=true
    fi

    if lsmod | grep -q "^$module"; then
        if $blacklist_found; then
            echo -e " Module $module is loaded and blacklisted...[${RED}PASS${RESET}]"
        else
            echo -e " Module $module is loaded but not blacklisted...[${RED}FAIL${RESET}]"
        fi
    else
        if $blacklist_found; then
            echo -e " Module $module is not loaded but blacklisted...[${GREEN}PASS${RESET}]"
        else
            echo -e  " Module $module is not loaded and not blacklisted...[${RED}FAIL${RESET}]"
        fi
    fi
}

for module in "${MODULE_LIST[@]}"; do
    kernel_module_audit "$module"
done

echo -e "➽ ${GREEN}Filesystem kernel module audit completed${RESET}"
sleep 10

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing filesystem partitions${RESET}...\n"
printf "╰─..★.──────────────────────────────────────╯\n"
sleep 5

check_partition() {
    mount | grep -E "\s$1\s" > /dev/null
    if [ $? -eq 0 ]; then
        echo -e " $1 is a separate partition...[${GREEN}PASS${RESET}]"
    else
        echo -e " $1 is not a separate partition...[${RED}FAIL${RESET}]"
    fi
}
check_option() {
    mount | grep -E "\s$1\s" | grep -q "$2"
    if [ $? -eq 0 ]; then
        echo -e " $2 option is set on $1...[${GREEN}PASS${RESET}]"
    else
        echo -e " $2 option is missing on $1...[${RED}FAIL${RESET}]"
    fi
}
partitions=("/tmp" "/var" "/var/tmp" "/var/log" "/var/log/audit" "/home" "/dev/shm")
for partition in "${partitions[@]}"; do
    check_partition "$partition"
    check_option "$partition" "nodev"
    check_option "$partition" "nosuid"
    if [[ "$partition" != "/var" && "$partition" != "/home" ]]; then
        check_option "$partition" "noexec"
    fi
done
echo -e "➽ ${GREEN}Filesystem partitions audit completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing package management${RESET}...\n"
printf "╰─..★.──────────────────────────────────────╯\n"
sleep 5

GPG_STATUS="FAIL"

for file in /etc/apt/trusted.gpg.d/*.{gpg,asc} /etc/apt/sources.list.d/*.{gpg,asc}; do
    if [ -f "$file" ]; then
        if gpg --list-packets "$file" 2>/dev/null | grep -q 'keyid:'; then
            GPG_STATUS="PASS"
            break
        fi
    fi
done

if [ "$GPG_STATUS" == "PASS" ]; then
    echo -e " Ensure GPG keys are configured...[${GREEN}$GPG_STATUS${RESET}]"
else
    echo -e " Ensure GPG keys are configured...[${RED}$GPG_STATUS${RESET}]"
fi

REPO_STATUS="PASS"
apt-cache policy > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e " Ensure package manager repositories are configured ...[${GREEN}PASS${RESET}]"
else
    REPO_STATUS="FAIL"
    echo -e " Ensure package manager repositories are configured ...[${RED}$REPO_STATUS${RESET}]"
fi

echo -e "➽ ${GREEN}Package management audit completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing mandatory access control${RESET}...\n"
printf "╰─..★.────────────────────────────────────────╯\n"
sleep 5
if dpkg-query -s apparmor apparmor-utils &>/dev/null; then
    echo -e " Ensure AppArmor & Apparmor-utils are installed...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure AppArmor & Apparmor-utils are installed...[${RED}FAIL${RESET}]"
fi

if grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1" &>/dev/null; then
    echo -e " Ensure all linux lines in GRUB have apparmor=1 ...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure all linux lines in GRUB have apparmor=1 ...[${GREEN}PASS${RESET}]"
fi

if grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor" &>/dev/null; then
    echo -e " Ensure all linux lines in GRUB have security=apparmor ...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure all linux lines in GRUB have security=apparmor ...[${GREEN}PASS${RESET}]"
fi

if apparmor_status | grep -q "profiles are loaded" && apparmor_status | grep -qE "enforce|complain"; then
    echo -e " Ensure all AppArmor Profiles are in enforce or complain mode ...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure all AppArmor Profiles are in enforce or complain mode ...[${RED}FAIL${RESET}]"
fi

echo -e "➽ ${GREEN}Mandatory access control audit completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing bootloader${RESET}...\n"
printf "╰─..★.──────────────────────────────────────╯\n"
sleep 5

USERNAME=$(grep "^set superusers=" /boot/grub/grub.cfg | cut -d '"' -f2)

grep -q "^set superusers=\"$USERNAME\"" /boot/grub/grub.cfg
SUPERUSER_STATUS=$?

awk -F. '/^\s*password/ {print $1"."$2"."$3}' /boot/grub/grub.cfg | grep -q "^password_pbkdf2 $USERNAME grub.pbkdf2.sha512"
PASSWORD_STATUS=$?

[[ $SUPERUSER_STATUS -eq 0 ]] && echo -e " Ensure bootloader superuser is set...[${GREEN}PASS${RESET}]" || echo -e " Ensure bootloader superuser is set...[${RED}FAIL${RESET}]"
[[ $PASSWORD_STATUS -eq 0 ]] && echo -e " Ensure bootloader password is set...[${GREEN}PASS${RESET}]" || echo -e " Ensure bootloader password is set...[${RED}FAIL${RESET}]"

OUTPUT=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /boot/grub/grub.cfg)

if echo "$OUTPUT" | grep -q "Access: (0600/-rw-------)" && echo "$OUTPUT" | grep -q "Uid: ( 0/ root)" && echo "$OUTPUT" | grep -q "Gid: ( 0/ root)"; then
    echo -e " Ensure access to bootloader config is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure access to bootloader config is configured...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Bootloader audit completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Additional Process Hardening${RESET}...\n"
printf "╰─..★.──────────────────────────────────────────────╯\n"
sleep 5

if [[ "$(sysctl kernel.randomize_va_space | awk '{print $3}')" -eq 2 ]]; then
    echo -e " Ensure address space layout randomization is enabled(kernel.randomize_va_space=2)...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure address space layout randomization is enabled...[${RED}FAIL${RESET}]"
fi

ptrace_value=$(sysctl kernel.yama.ptrace_scope | awk '{print $3}')

if [[ "$ptrace_value" -ge 1 && "$ptrace_value" -le 3 ]]; then
    echo -e " Ensure ptrace_scope is restricted(kernel.yama.ptrace_scope=$ptrace_value)...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure ptrace_scope is restricted...[${RED}FAIL${RESET}]"
fi

if find /etc/security/limits.d -type f -exec grep -qP '^\s*\*\s+hard\s+core\s+0\b' {} \; 2>/dev/null &&
   [[ "$(sysctl fs.suid_dumpable | awk '{print $3}')" -eq 0 ]]; then
    echo -e " Ensure core dumps are restricted...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure core dumps are restricted...[${RED}FAIL${RESET}]"
fi

dpkg-query -s prelink &>/dev/null
if [ $? -eq 0 ]; then
    echo -e " Ensure prelink is not installed...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure prelink is not installed...[${GREEN}PASS${RESET}]"
fi

dpkg-query -s apport &>/dev/null

if [ $? -eq 0 ]; then
    enabled_status=$(grep -i '^\s*enabled\s*=\s*1' /etc/default/apport)

    if [ -n "$enabled_status" ]; then
        echo -e " Ensure Automatic Error Reporting is not enabled...[${RED}FAIL${RESET}]"
    else
        echo -e " Ensure Automatic Error Reporting is not enabled...[${GREEN}PASS${RESET}]"
    fi

    systemctl is-active --quiet apport.service
    if [ $? -eq 0 ]; then
        echo -e " Ensure apport service is not active...[${RED}FAIL${RESET}]"
    else
        echo -e " Ensure apport service is not active...[${GREEN}PASS${RESET}]"
    fi
else
    echo -e " Ensure apport is not installed...[${GREEN}PASS${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing Additional Process Hardening completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing command Line Warning Banners${RESET}...\n"
printf "╰─..★.──────────────────────────────────────────────╯\n"
sleep 5

audit_failed=0

if [ ! -s /etc/issue ]; then
    audit_failed=1
fi
if grep -qE "Ubuntu|Debian GNU/Linux" /etc/issue; then
    audit_failed=1
fi
if [ "$audit_failed" -eq 1 ]; then
    echo -e " Ensure local login warning banner is configured...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure local login warning banner is configured...[${GREEN}PASS${RESET}]"
fi
scripts=(
    "/etc/update-motd.d/50-landscape-sysinfo"
    "/etc/update-motd.d/90-updates-available"
    "/etc/update-motd.d/98-reboot-required"
    "/etc/update-motd.d/50-motd-news"
)
audit_failed=0
for script in "${scripts[@]}"; do
    if [ -x "$script" ]; then
        audit_failed=1
        break
    fi
done
if [ "$(stat -c "%a" /etc/motd 2>/dev/null)" != "640" ]; then
    echo -e " Ensure access to /etc/motd is configured...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure access to /etc/motd is configured...[${GREEN}PASS${RESET}]"
fi
if [ "$audit_failed" -eq 1 ]; then
    echo -e " Ensure message of the day is configured...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure message of the day is configured...[${GREEN}PASS${RESET}]"
fi
audit_failed=0
if [ ! -s /etc/issue ]; then
    audit_failed=1
fi
if grep -qE "Ubuntu|Debian GNU/Linux" /etc/issue; then
    audit_failed=1
fi
if [ "$audit_failed" -eq 1 ]; then
    echo -e " Ensure remote login warning banner is configured properly...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure remote login warning banner is configured properly...[${GREEN}PASS${RESET}]"
fi
if [ "$(stat -c "%a" /etc/issue 2>/dev/null)" != "644" ]; then
    echo -e " Ensure access to /etc/issue is configured...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure access to /etc/issue is configured...[${GREEN}PASS${RESET}]"
fi
if [ "$(stat -c "%a" /etc/issue.net 2>/dev/null)" != "644" ]; then
    echo -e " Ensure access to /etc/issue.net is configured...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure access to /etc/issue.net is configured...[${GREEN}PASS${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing command Line Warning Banners completed${RESET}"
sleep 5

printf "${BLUE}[+] Filesystem${RESET}\n"
printf "╭──────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing GNOME Display Manager${RESET}...\n"
printf "╰─..★.──────────────────────────────────────────╯\n"
sleep 5

if dpkg-query -W -f='${Status}\n' gdm3 2>/dev/null | grep -q "installed"; then
    echo -e " Ensure GDM is removed...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure GDM is removed...[${GREEN}PASS${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing GNOME Display Manager completed${RESET}"
sleep 5

printf "${BLUE}[+] Services${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Server Services${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5
if dpkg-query -s autofs &>/dev/null; then
    if systemctl is-enabled autofs.service 2>/dev/null | grep -q 'enabled'; then
        echo -e " autofs.service is enabled...[${RED}FAIL${RESET}] "
    fi
    if systemctl is-active autofs.service 2>/dev/null | grep -q '^active'; then
        echo -e " autofs.service is active...[${RED}FAIL${RESET}] "
    fi
fi
echo -e " Ensure autofs services are not in use...[${GREEN}PASS${RESET}]"
if dpkg-query -s avahi-daemon &>/dev/null; then
    if systemctl is-enabled avahi-daemon.service avahi-daemon.socket 2>/dev/null | grep -q 'enabled'; then
        echo -e " avahi-daemon service/socket is enabled...[${RED}FAIL${RESET}]"
    fi
    if systemctl is-active avahi-daemon.service avahi-daemon.socket 2>/dev/null | grep -q '^active'; then
        echo -e " avahi-daemon service/socket is active...[${RED}FAIL${RESET}]"
    fi
fi
echo -e " Ensure avahi daemon services are not in use...[${GREEN}PASS${RESET}]"
if ! dpkg-query -s isc-dhcp-server &>/dev/null; then
    echo -e " Ensure dhcp server services are not in use...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure dhcp server services are not in use...[${RED}FAIL${RESET}]"
fi
if ! dpkg-query -s bind9 &>/dev/null && \
   ! systemctl is-enabled named.service 2>/dev/null | grep -q 'enabled' && \
   ! systemctl is-active named.service 2>/dev/null | grep -q '^active'; then
    echo -e " Ensure dns server services are not in use...${GREEN}PASS${RESET}"
else
    echo -e " Ensure dns server services are not in use...${RED}FAIL${RESET}"
fi
if dpkg-query -s dnsmasq &>/dev/null && \
   (systemctl is-enabled dnsmasq.service 2>/dev/null | grep -q 'enabled' || \
    systemctl is-active dnsmasq.service 2>/dev/null | grep -q '^active'); then
    echo -e " Ensure dnsmasq services are not in use...[${RED}FAIL${RESET}]"  
else
    echo -e " Ensure dnsmasq services are not in use...[${GREEN}PASS${RESET}]" 
fi
if dpkg-query -s vsftpd &>/dev/null && \
   (systemctl is-enabled vsftpd.service 2>/dev/null | grep -q 'enabled' || \
    systemctl is-active vsftpd.service 2>/dev/null | grep -q '^active'); then
    echo -e " Ensure ftp server services are not in use...[${RED}FAIL${RESET}]" 
else
    echo -e " Ensure ftp server services are not in use...[${GREEN}PASS${RESET}]"
fi
if ! dpkg-query -s slapd &>/dev/null; then
    echo -e  " Ensure ldap server services are not in use...[${GREEN}PASS${RESET}]" 
else
    if systemctl is-enabled slapd.service 2>/dev/null | grep -q 'enabled' || \
       systemctl is-active slapd.service 2>/dev/null | grep -q '^active'; then
        echo -e " Ensure ldap server services are not in use...[${RED}FAIL${RESET}]" 
    else
        echo -e " Ensure ldap server services are not in use...[${GREEN}PASS${RESET}]"  
    fi
fi
if dpkg-query -s ypserv &>/dev/null || \
   systemctl is-enabled ypserv.service 2>/dev/null | grep -q 'enabled' || \
   systemctl is-active ypserv.service 2>/dev/null | grep -q '^active'; then
    echo -e " Ensure nis server services are not in use...[${RED}FAIL${RESET}]" 
else
    echo -e " Ensure nis server services are not in use...[${GREEN}PASS${RESET}]" 
fi

if dpkg-query -s rpcbind &>/dev/null || \
   systemctl is-enabled rpcbind.socket rpcbind.service 2>/dev/null | grep -q 'enabled' || \
   systemctl is-active rpcbind.socket rpcbind.service 2>/dev/null | grep -q '^active'; then
    echo -e " Ensure rpcbind services are not in use...[${RED}FAIL${RESET}]" 
else
    echo -e " Ensure rpcbind services are not in use...[${GREEN}PASS${RESET}]" 
fi

if dpkg-query -s tftpd-hpa &>/dev/null || \
   systemctl is-enabled tftpd-hpa.service 2>/dev/null | grep -q 'enabled' || \
   systemctl is-active tftpd-hpa.service 2>/dev/null | grep -q '^active'; then
    echo -e " Ensure tftp server services are not in use...[${RED}FAIL${RESET}]" 
else
    echo -e " Ensure tftp server services are not in use...[${GREEN}PASS${RESET}]" 
fi
if dpkg-query -s squid &>/dev/null || \
   systemctl is-enabled squid.service 2>/dev/null | grep -q 'enabled' || \
   systemctl is-active squid.service 2>/dev/null | grep -q '^active'; then
    echo -e " Ensure web proxy server services are not in use...[${RED}FAIL${RESET}]" 
else
    echo -e " Ensure web proxy server services are not in use...[${GREEN}PASS${RESET}]" 
fi
if dpkg-query -s nfs-kernel-server &>/dev/null || \
   systemctl is-enabled nfs-server.service 2>/dev/null | grep -q 'enabled' || \
   systemctl is-active nfs-server.service 2>/dev/null | grep -q '^active'; then
    echo -e " Ensure network file system services are not in use...[${RED}FAIL${RESET}]" 
else
    echo -e " Ensure network file system services are not in use...[${GREEN}PASS${RESET}]" 
fi
echo -e "➽ ${GREEN}Auditing Server Services completed${RESET}"
sleep 5

printf "${BLUE}[+] Services${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Client Services${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

if dpkg-query -s nis &>/dev/null; then
    echo -e " Ensure NIS Client is not installed...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure NIS Client is not installed...[${GREEN}PASS${RESET}]"
fi
if dpkg-query -s rsh-client &>/dev/null; then
    echo -e " Ensure rsh client is not installed...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure rsh client is not installed...[${GREEN}PASS${RESET}]"
fi
if dpkg-query -s talk &>/dev/null; then
    echo -e " Ensure talk client is not installed...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure talk client is not installed...[${GREEN}PASS${RESET}]"
fi
if dpkg-query -l | grep -E 'telnet|inetutils-telnet' &>/dev/null; then
    echo -e " Ensure telnet client is not installed...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure telnet client is not installed...[${GREEN}PASS${RESET}]"
fi
if dpkg-query -s ldap-utils &>/dev/null; then
    echo -e " Ensure ldap client is not installed...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure ldap client is not installed...[${GREEN}PASS${RESET}]"
fi
if dpkg-query -l | grep -E 'ftp|tnftp' &>/dev/null; then
    echo -e " Ensure ftp client is not installed...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure ftp client is not installed...[${GREEN}PASS${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing client Services completed${RESET}"
sleep 5

printf "${BLUE}[+] Services${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Time Synchronization${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

if systemctl is-enabled chrony.service &>/dev/null || systemctl is-active chrony.service &>/dev/null; then
    chrony_enabled=true
else
    chrony_enabled=false
fi

if systemctl is-enabled systemd-timesyncd.service &>/dev/null || systemctl is-active systemd-timesyncd.service &>/dev/null; then
    timesyncd_enabled=true
else
    timesyncd_enabled=false
fi
if [[ "$chrony_enabled" == true && "$timesyncd_enabled" == true ]]; then
    echo -e " Ensure a single time synchronization daemon is in use...[${RED}FAIL${RESET}]"
elif [[ "$chrony_enabled" == false && "$timesyncd_enabled" == false ]]; then
    echo -e " Ensure a single time synchronization daemon is in use...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure a single time synchronization daemon is in use...[${GREEN}PASS${RESET}]"
fi
if grep -Eqi '^\s*(server|pool)\s+' /etc/chrony/chrony.conf /etc/chrony/sources.d/*.sources 2>/dev/null; then
    echo -e " Ensure Chrony is configured with an authorized timeserver...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure Chrony is configured with an authorized timeserver...[${RED}FAIL${RESET}]"
fi
if ps -ef | awk '(/[c]hronyd/ && $1!="_chrony") { exit 1 }'; then
    echo -e " Ensure Chrony is running as user _chrony...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure Chrony is running as user _chrony...[${RED}FAIL${RESET}]"
fi
if systemctl is-enabled chrony.service &>/dev/null && systemctl is-active chrony.service &>/dev/null; then
    echo -e " Ensure Chrony is enabled and running...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure Chrony is enabled and running...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing Time Synchronizatio completed${RESET}"
sleep 5

printf "${BLUE}[+] Services${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing job schedulers${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

if systemctl list-unit-files | awk '$1~/^crond?\.service/{print $2}' | grep -qi "enabled" && \
   systemctl list-units | awk '$1~/^crond?\.service/{print $3}' | grep -qi "active"; then
    echo -e " Ensure cron daemon is enabled and active...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure cron daemon is enabled and active...[${RED}FAIL${RESET}]"
fi
if [ -f /etc/crontab ]; then
    perms=$(stat -Lc '%a' /etc/crontab)
    owner=$(stat -Lc '%u' /etc/crontab)
    group=$(stat -Lc '%g' /etc/crontab)

    if [[ "$perms" == "600" && "$owner" == "0" && "$group" == "0" ]]; then
        echo -e " Ensure permissions on /etc/crontab are configured...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure permissions on /etc/crontab are configured...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " • /etc/crontab file does not exist, skipping check...[${YELLOW}SKIP${RESET}]"
fi
if [ -d /etc/cron.hourly ]; then
    perms=$(stat -Lc '%a' /etc/cron.hourly)
    owner=$(stat -Lc '%u' /etc/cron.hourly)
    group=$(stat -Lc '%g' /etc/cron.hourly)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        echo -e " Ensure permissions on /etc/cron.hourly are configured...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure permissions on /etc/cron.hourly are configured...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " /etc/cron.hourly directory does not exist, skipping check...[${YELLOW}SKIP${RESET}]"
fi
if [ -d /etc/cron.hourly ]; then
    perms=$(stat -Lc '%a' /etc/cron.hourly)
    owner=$(stat -Lc '%u' /etc/cron.hourly)
    group=$(stat -Lc '%g' /etc/cron.hourly)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        echo -e " Ensure permissions on /etc/cron.hourly are configured...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure permissions on /etc/cron.hourly are configured...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " /etc/cron.hourly directory does not exist, skipping check...[${YELLOW}SKIP${RESET}]"
fi
if [ -d /etc/cron.daily ]; then
    perms=$(stat -Lc '%a' /etc/cron.daily)
    owner=$(stat -Lc '%u' /etc/cron.daily)
    group=$(stat -Lc '%g' /etc/cron.daily)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        echo -e " Ensure permissions on /etc/cron.daily are configured...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure permissions on /etc/cron.daily are configured...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " /etc/cron.daily directory does not exist, skipping check...[${YELLOW}SKIP${RESET}]"
fi
if [ -d /etc/cron.weekly ]; then
    perms=$(stat -Lc '%a' /etc/cron.weekly)
    owner=$(stat -Lc '%u' /etc/cron.weekly)
    group=$(stat -Lc '%g' /etc/cron.weekly)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        echo -e " Ensure permissions on /etc/cron.weekly are configured...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure permissions on /etc/cron.weekly are configured...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " /etc/cron.weekly directory does not exist, skipping check...[${YELLOW}SKIP${RESET}]"
fi
if [ -d /etc/cron.monthly ]; then
    perms=$(stat -Lc '%a' /etc/cron.monthly)
    owner=$(stat -Lc '%u' /etc/cron.monthly)
    group=$(stat -Lc '%g' /etc/cron.monthly)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        echo -e " Ensure permissions on /etc/cron.monthly are configured...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure permissions on /etc/cron.monthly are configured...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " /etc/cron.monthly directory does not exist, skipping check...[${YELLOW}SKIP${RESET}]"
fi
if [ -d /etc/cron.d ]; then
    perms=$(stat -Lc '%a' /etc/cron.d)
    owner=$(stat -Lc '%u' /etc/cron.d)
    group=$(stat -Lc '%g' /etc/cron.d)

    if [[ "$perms" == "700" && "$owner" == "0" && "$group" == "0" ]]; then
        echo -e " Ensure permissions on /etc/cron.d are configured...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure permissions on /etc/cron.d are configured...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " /etc/cron.d directory does not exist, skipping check...[${YELLOW}SKIP${RESET}]"
fi
if [ -e "/etc/cron.allow" ]; then
    stat -Lc 'Access: (%a) Owner: (%U) Group: (%G)' /etc/cron.allow | grep -E "Access: \(640\) Owner: \(root\) Group: \(root\)|Access: \(640\) Owner: \(root\) Group: \(crontab\)" \
    && echo -e " Ensure /etc/cron.allow is correctly configured...[${GREEN}PASS${RESET}]" \
    || echo -e " Ensure /etc/cron.allow permissions are incorrect...[${RED}FAIL${RESET}]"
else
    echo -e " /etc/cron.allow does not exist...[${RED}WARNING${RESET}]"
fi
if [ -e "/etc/cron.deny" ]; then
    stat -Lc 'Access: (%a) Owner: (%U) Group: (%G)' /etc/cron.deny | grep -E "Access: \(640\) Owner: \(root\) Group: \(root\)|Access: \(640\) Owner: \(root\) Group: \(crontab\)" \
    && echo -e " Ensure /etc/cron.deny is correctly configured...[${GREEN}PASS${RESET}]" \
    || echo -e " Ensure /etc/cron.deny permissions are incorrect...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure /etc/cron.deny does not exist...[${GREEN}PASS${RESET}]"
fi

if [ -e "/etc/at.allow" ]; then
    stat -Lc 'Access: (%a) Owner: (%U) Group: (%G)' /etc/at.allow | grep -E "Access: \(640\) Owner: \(root\) Group: \(daemon\)|Access: \(640\) Owner: \(root\) Group: \(root\)" \
    && echo -e " Ensure /etc/at.allow is correctly configured...[${GREEN}PASS${RESET}]" \
    || echo -e " Ensure /etc/at.allow permissions are incorrect...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure /etc/at.allow does not exist...[${RED}WARNING${RESET}]"
fi

if [ -e "/etc/at.deny" ]; then
    stat -Lc 'Access: (%a) Owner: (%U) Group: (%G)' /etc/at.deny | grep -E "Access: \(640\) Owner: \(root\) Group: \(daemon\)|Access: \(640\) Owner: \(root\) Group: \(root\)" \
    && echo -e " Ensure /etc/at.deny is correctly configured...[${GREEN}PASS${RESET}]" \
    || echo -e " Ensure /etc/at.deny permissions are incorrect...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure /etc/at.deny does not exist...[${GREEN}PASS${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing job schedulers completed${RESET}"
sleep 5

printf "${BLUE}[+] Network${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Network Devices${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

ipv6_status=$(sysctl -n net.ipv6.conf.all.disable_ipv6)
ipv6_default_status=$(sysctl -n net.ipv6.conf.default.disable_ipv6)
if [ "$ipv6_status" -eq 0 ] && [ "$ipv6_default_status" -eq 0 ]; then
    ipv6_status="${GREEN}enabled${RESET}"
    if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs "net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*0\b" && \
       sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs "net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*0\b"; then
        ipv6_config="${GREEN}configured${RESET}"
    else
        ipv6_config="${RED}not configured${RESET}"
    fi
else
    ipv6_status="${RED}disabled${RESET}"
    ipv6_config="${RED}not configured${RESET}"
fi
echo -e " Ensure IPv6 status is identified...[${ipv6_status}] [${ipv6_config}]"

if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
    l_output=""
    l_output2=""
    
    module_chk() {
        l_loadable="$(modprobe -n -v "$l_mname")"
        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable: \"$l_loadable\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable: \"$l_loadable\""
        fi

        if ! lsmod | grep "$l_mname" > /dev/null 2>&1; then
            l_output="$l_output\n - module: \"$l_mname\" is not loaded"
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loaded"
        fi

        if modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mname\b"; then
            l_output="$l_output\n - module: \"$l_mname\" is deny listed in: \"$(grep -Pl -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*)\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is not deny listed"
        fi
    }

    l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)"; done | sort -u)
    for l_mname in $l_dname; do
        module_chk
    done
    if [ -z "$l_output2" ]; then
        echo -e " Ensure wireless interfaces are disabled...[${GREEN}PASS${RESET}] No active wireless interfaces detected."
    else
        echo -e " Ensure wireless interfaces are disabled...[${RED}FAIL${RESET}] Wireless interfaces are active."
    fi
else
    echo -e " No wireless interfaces found...[${GREEN}SKIPPED${RESET}]"
fi
if dpkg-query -s bluez &>/dev/null; then
    if systemctl is-enabled bluetooth.service 2>/dev/null | grep -q 'enabled'; then
        if systemctl is-active bluetooth.service 2>/dev/null | grep -q '^active'; then
            echo -e " Ensure bluetooth services are not in use...[${RED}FAIL${RESET}]"
        else
            echo -e " Ensure bluetooth services are not in use...[${RED}FAIL${RESET}]"
        fi
    else
        echo -e " Ensure bluetooth services are not in use...[${GREEN}PASS${RESET}]"
    fi
else
    echo -e " Ensure bluetooth services are not in use...[${GREEN}PASS${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing network devices completed${RESET}"
sleep 5

printf "${BLUE}[+] Network${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Network kernel modules${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

l_mod_name="dccp"
audit_result="pass"
if lsmod | grep -q "^$l_mod_name"; then
    audit_result="fail"
fi
if ! grep -Pq -- "^\s*install\s+$l_mod_name\s+/bin/false" /etc/modprobe.d/*.conf 2>/dev/null; then
    audit_result="fail"
fi
if ! grep -Pq -- "^\s*blacklist\s+$l_mod_name" /etc/modprobe.d/*.conf 2>/dev/null; then
    audit_result="fail"
fi
if [[ "$audit_result" == "pass" ]]; then
    echo -e " Ensure dccp kernel module is not available...[${GREEN}PASS${RESET}]" 
else
    echo -e " Ensure dccp kernel module is not available...[${GREEN}FAIL${RESET}]" 
fi
l_mod_name="sctp"
audit_result="pass"
if lsmod | grep -q "^$l_mod_name"; then
    audit_result="fail"
fi
if ! grep -Pq -- "^\s*install\s+$l_mod_name\s+/bin/false" /etc/modprobe.d/*.conf 2>/dev/null; then
    audit_result="fail"
fi
if ! grep -Pq -- "^\s*blacklist\s+$l_mod_name" /etc/modprobe.d/*.conf 2>/dev/null; then
    audit_result="fail"
fi
if [[ "$audit_result" == "pass" ]]; then
    echo -e " Ensure sctp kernel module is not available......[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sctp kernel module is not available......[${RED}FAIL${RESET}]"
fi
l_mod_name="rds"
audit_result="pass"
if lsmod | grep -q "^$l_mod_name"; then
    audit_result="fail"
fi
if ! grep -Pq -- "^\s*install\s+$l_mod_name\s+/bin/false" /etc/modprobe.d/*.conf 2>/dev/null; then
    audit_result="fail"
fi
if ! grep -Pq -- "^\s*blacklist\s+$l_mod_name" /etc/modprobe.d/*.conf 2>/dev/null; then
    audit_result="fail"
fi
if [[ "$audit_result" == "pass" ]]; then
    echo -e " Ensure rds kernel module is not available......[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure rds kernel module is not available......[${RED}FAIL${RESET}]"
fi
l_mod_name="sctp"
audit_result="pass"
if lsmod | grep -q "^$l_mod_name"; then
    audit_result="fail"
fi
if ! grep -Pq -- "^\s*install\s+$l_mod_name\s+/bin/false" /etc/modprobe.d/*.conf 2>/dev/null; then
    audit_result="fail"
fi
if ! grep -Pq -- "^\s*blacklist\s+$l_mod_name" /etc/modprobe.d/*.conf 2>/dev/null; then
    audit_result="fail"
fi
if [[ "$audit_result" == "pass" ]]; then
    echo -e " Ensure sctp kernel module is not available......[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sctp kernel module is not available......[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing network kernel modules completed${RESET}"
sleep 5

printf "${BLUE}[+] Network${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Network kernel Parameters${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
sleep 5

ipv4_forwarding=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
ipv6_forwarding=$(sysctl net.ipv6.conf.all.forwarding | awk '{print $3}')
ipv4_configured=$(grep -E "^\s*net.ipv4.ip_forward\s*=" /etc/sysctl.conf /etc/sysctl.d/*.conf | awk -F= '{print $2}' | tr -d ' ')
ipv6_configured=$(grep -E "^\s*net.ipv6.conf.all.forwarding\s*=" /etc/sysctl.conf /etc/sysctl.d/*.conf | awk -F= '{print $2}' | tr -d ' ')
if [[ "$ipv4_forwarding" == "0" ]] && [[ "$ipv4_configured" == "0" ]]; then
    echo -e " IPv4 forwarding is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " IPv4 forwarding is enabled or not correctly configured...[${RED}FAIL${RESET}]"
fi
if [[ "$ipv6_forwarding" == "0" ]] && [[ "$ipv6_configured" == "0" ]]; then
    echo -e " IPv6 forwarding is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " IPv6 forwarding is enabled or not correctly configured...[${RED}FAIL${RESET}]"
fi
ipv4_all_redirects=$(sysctl net.ipv4.conf.all.send_redirects | awk '{print $3}')
ipv4_default_redirects=$(sysctl net.ipv4.conf.default.send_redirects | awk '{print $3}')
ipv4_all_configured=$(grep -E "^\s*net.ipv4.conf.all.send_redirects\s*=" /etc/sysctl.conf /etc/sysctl.d/*.conf | awk -F= '{print $2}' | tr -d ' ' 2>/dev/null)
ipv4_default_configured=$(grep -E "^\s*net.ipv4.conf.default.send_redirects\s*=" /etc/sysctl.conf /etc/sysctl.d/*.conf | awk -F= '{print $2}' | tr -d ' ' 2>/dev/null)
if [[ "$ipv4_all_redirects" == "0" ]] && [[ "$ipv4_all_configured" == "0" ]]; then
    echo -e " IPv4 all send redirects is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " IPv4 all send redirects is enabled or not correctly configured...[${RED}FAIL${RESET}]"
fi
if [[ "$ipv4_default_redirects" == "0" ]] && [[ "$ipv4_default_configured" == "0" ]]; then
    echo -e " IPv4 default send redirects is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " IPv4 default send redirects is enabled or not correctly configured...[${RED}FAIL${RESET}]"
fi
icmp_bogus=$(sysctl net.ipv4.icmp_ignore_bogus_error_responses | awk '{print $3}')
icmp_bogus_configured=$(grep -E "^\s*net.ipv4.icmp_ignore_bogus_error_responses\s*=" /etc/sysctl.conf /etc/sysctl.d/*.conf | awk -F= '{print $2}' | tr -d ' ' 2>/dev/null)
if [[ "$icmp_bogus" == "1" ]] && [[ "$icmp_bogus_configured" == "1" ]]; then
    echo -e " ICMP ignore bogus error responses is set correctly...[${GREEN}PASS${RESET}]"
else
    echo -e " ICMP ignore bogus error responses is NOT set correctly...[${RED}FAIL${RESET}]"
fi
current_value=$(sysctl net.ipv4.icmp_echo_ignore_broadcasts | awk '{print $3}')
config_files=(/etc/sysctl.conf /etc/sysctl.d/*.conf)
config_set=false
for file in "${config_files[@]}"; do
    if grep -q "^net.ipv4.icmp_echo_ignore_broadcasts = 1" "$file" 2>/dev/null; then
        config_set=true
        break
    fi
done
if [[ "$current_value" -eq 1 && "$config_set" == true ]]; then
    echo -e " Ensure broadcast icmp requests are ignored...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure broadcast icmp requests are ignored...[${RED}FAIL${RESET}]"
fi
if sysctl -n net.ipv4.conf.all.accept_redirects | grep -q "^0$" && \
   sysctl -n net.ipv4.conf.default.accept_redirects | grep -q "^0$" && \
   sysctl -n net.ipv6.conf.all.accept_redirects | grep -q "^0$" && \
   sysctl -n net.ipv6.conf.default.accept_redirects | grep -q "^0$"; then
    echo -e " Ensure icmp redirects are not accepted...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure icmp redirects are not accepted...[${RED}FAIL${RESET}]"
fi
current_value_all=$(sysctl net.ipv4.conf.all.secure_redirects | awk '{print $3}')
current_value_default=$(sysctl net.ipv4.conf.default.secure_redirects | awk '{print $3}')

if [[ "$current_value_all" -eq 0 && "$current_value_default" -eq 0 ]]; then
    echo -e " Ensure secure icmp redirects are not accepted...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure secure icmp redirects are not accepted...[${RED}FAIL${RESET}]"
fi
current_value_all=$(sysctl net.ipv4.conf.all.rp_filter | awk '{print $3}')
current_value_default=$(sysctl net.ipv4.conf.default.rp_filter | awk '{print $3}')
if [[ "$current_value_all" -eq 1 && "$current_value_default" -eq 1 ]]; then
    echo -e " Ensure reverse path filtering is enabled...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure reverse path filtering is enabled...[${RED}FAIL${RESET}]"
fi
current_value_ipv4_all=$(sysctl net.ipv4.conf.all.accept_source_route | awk '{print $3}')
current_value_ipv4_default=$(sysctl net.ipv4.conf.default.accept_source_route | awk '{print $3}')
current_value_ipv6_all=$(sysctl net.ipv6.conf.all.accept_source_route | awk '{print $3}')
current_value_ipv6_default=$(sysctl net.ipv6.conf.default.accept_source_route | awk '{print $3}')
if [[ "$current_value_ipv4_all" -eq 0 && "$current_value_ipv4_default" -eq 0 && "$current_value_ipv6_all" -eq 0 && "$current_value_ipv6_default" -eq 0 ]]; then
    echo -e " Ensure source routed packets are not accepted...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure source routed packets are not accepted...[${RED}FAIL${RESET}]"
fi
current_value_ipv4_all=$(sysctl net.ipv4.conf.all.log_martians | awk '{print $3}')
current_value_ipv4_default=$(sysctl net.ipv4.conf.default.log_martians | awk '{print $3}')
if [[ "$current_value_ipv4_all" -eq 1 && "$current_value_ipv4_default" -eq 1 ]]; then
    echo -e " Ensure suspicious packets are logged...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure suspicious packets are logged...[${RED}FAIL${RESET}]"
fi
current_value=$(sysctl net.ipv4.tcp_syncookies | awk '{print $3}')
if [[ "$current_value" -eq 1 ]]; then
    echo -e " Ensure TCP SYN cookies are enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure TCP SYN cookies are enabled...[${RED}FAIL${RESET}]"
fi
current_value_all=$(sysctl net.ipv6.conf.all.accept_ra | awk '{print $3}')
current_value_default=$(sysctl net.ipv6.conf.default.accept_ra | awk '{print $3}')
if [[ "$current_value_all" -eq 0 && "$current_value_default" -eq 0 ]]; then
    echo -e " Ensure IPv6 router advertisements are not accepted...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure IPv6 router advertisements are not accepted...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing network kernel parameters completed${RESET}"
sleep 5

printf "${BLUE}[+] Host Based Firewall${RESET}\n"
printf "╭─────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing single firewall utility${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────╯\n"
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
if [ ${#active_firewalls[@]} -eq 1 ]; then
    echo -e " ${active_firewalls[0]} Ensure a single firewall configuration utility is in use...[${GREEN}PASS${RESET}]"
elif [ ${#active_firewalls[@]} -eq 0 ]; then
    echo -e " Ensure a single firewall configuration utility is in use...[${GREEN}FAIL${RESET}]"
elif [ ${#active_firewalls[@]} -gt 1 ]; then
    echo -e " Multiple firewalls are in use...[${GREEN}WARNING${RESET}]${active_firewalls[*]}"
fi
echo -e "➽ ${GREEN}Auditing single firewall configuration utility completed${RESET}"
sleep 5

printf "${BLUE}[+] Host Based Firewall${RESET}\n"
printf "╭───────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing UncomplicatedFirewall${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────────╯\n"
sleep 5

if dpkg-query -s ufw &>/dev/null; then
    echo -e " Ensure ufw is installed...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure ufw is installed...[${RED}FAIL${RESET}]"
fi
if dpkg-query -s iptables-persistent &>/dev/null; then
    echo -e " Ensure iptables-persistent is not installed with ufw...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure iptables-persistent is not installed with ufw...[${RED}FAIL${RESET}]"
fi
if systemctl is-enabled --quiet ufw && systemctl is-active --quiet ufw && ufw status | grep -q "Status: active"; then
    echo -e " Ensure ufw service is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure ufw service is enabled...[${RED}FAIL${RESET}]"
fi
UFW_STATUS=$(ufw status verbose | sed 's/  */ /g')
if echo "$UFW_STATUS" | grep -qE 'Anywhere on lo ALLOW IN Anywhere' &&
   echo "$UFW_STATUS" | grep -qE 'Anywhere DENY IN 127.0.0.0/8' &&
   echo "$UFW_STATUS" | grep -qE 'Anywhere \(v6\) on lo ALLOW IN Anywhere \(v6\)' &&
   echo "$UFW_STATUS" | grep -qE 'Anywhere \(v6\) DENY IN ::1' &&
   echo "$UFW_STATUS" | grep -qE 'Anywhere ALLOW OUT Anywhere on lo' &&
   echo "$UFW_STATUS" | grep -qE 'Anywhere \(v6\) ALLOW OUT Anywhere \(v6\) on lo'; then
    echo -e " Ensure ufw loopback traffic is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure ufw loopback traffic is configured...[${RED}FAIL${RESET}]"
fi
if ufw status verbose | grep -qE "Default: deny \(incoming\), allow \(outgoing\)"; then
    echo -e " Ensure ufw outbound connections are configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure ufw outbound connections are configured...[${RED}FAIL${RESET}]"
fi
open_ports=$(ufw status verbose | grep -Po '^\h*\d+\b' | sort -u)
system_ports=$(ss -tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/ && $5!~/\[?::1\]?:/) {split($5, a, ":"); print a[2]}' | sort -u)
diff_ports=$(comm -23 <(echo "$system_ports") <(echo "$open_ports"))

if [ -z "$diff_ports" ]; then
    echo -e " Ensure ufw firewall rules exist for all open ports...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure ufw firewall rules exist for all open ports...[${RED}FAIL${RESET}]"
fi
if ufw status verbose | grep -qE "Default: deny \(incoming\), deny \(outgoing\), disabled \(routed\)"; then
    echo -e " Ensure ufw default deny firewall policy...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure ufw default deny firewall policy...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing uncomplicatedfirewall completed${RESET}"
sleep 5

printf "${BLUE}[+] Access Control${RESET}\n"
printf "╭───────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing ssh server${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────────╯\n"
sleep 5

failed=0
for file in /etc/ssh/sshd_config $(find /etc/ssh/sshd_config.d -type f -name '*.conf' 2>/dev/null); do
    [ -e "$file" ] || continue
    mode=$(stat -c '%a' "$file")
    user=$(stat -c '%U' "$file")
    group=$(stat -c '%G' "$file")
    if [ "$mode" -gt 600 ] || [ "$user" != "root" ] || [ "$group" != "root" ]; then
        failed=1
    fi
done
if [ "$failed" -eq 0 ]; then
    echo -e "  Ensure permissions on SSH config files...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure permissions on SSH config files...[${RED}FAIL${RESET}]"
fi
ssh_group_name=$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)
for file in $(find /etc/ssh -type f -name '*_key' 2>/dev/null); do
    if ssh-keygen -lf &>/dev/null "$file"; then
        file_mode=$(stat -c '%a' "$file")
        file_owner=$(stat -c '%U' "$file")
        file_group=$(stat -c '%G' "$file")
        if [ "$file_owner" != "root" ] || [[ ! "$file_group" =~ $ssh_group_name|root ]] || [ "$file_mode" -gt 640 ]; then
            echo -e " Ensure permissions on SSH private host key files...[${RED}FAIL${RESET}]"
        fi
    fi
done
echo -e " Ensure permissions on SSH private host key files...[${GREEN}PASS${RESET}]"
ssh_group_name=$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)
l_pmask="0133"
l_maxperm="$(printf '%o' $((0777 & ~$l_pmask)))"
for file in $(find /etc/ssh -type f -name '*_key.pub' 2>/dev/null); do
    file_mode=$(stat -c '%a' "$file")
    file_owner=$(stat -c '%U' "$file")
    file_group=$(stat -c '%G' "$file")
    
    if [ $((file_mode & $l_pmask)) -gt 0 ] || [ "$file_owner" != "root" ] || [ "$file_group" != "root" ]; then
        echo -e " Ensure permissions on SSH public host key files...[${RED}FAIL${RESET}]"
    fi
done
echo -e " Ensure permissions on SSH public host key files...[${GREEN}PASS${RESET}]"
if sshd -T | grep -Pqi '^\h*(allow|deny)(users|groups)\h+\H+'; then
    echo -e " Ensure sshd access is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd access is configured...[${RED}FAIL${RESET}]"
fi
BANNER_FILE=$(sshd -T | awk '$1 == "banner" {print $2}')
if [ -n "$BANNER_FILE" ] && [ -e "$BANNER_FILE" ]; then
    if ! grep -qP "(\\v|\\r|\\m|\\s)" "$BANNER_FILE" 2>/dev/null; then
        echo -e " Ensure sshd Banner is configured...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure sshd Banner is configured...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " Ensure sshd Banner is configured...[${RED}FAIL${RESET}]"
fi
weak_ciphers=$(sshd -T | grep -Pi -- '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se|chacha20-poly1305@openssh\.com)\b')
if [ -n "$weak_ciphers" ]; then
    echo -e " Ensure sshd Ciphers are configured...Weak ciphers detected:[${RED}FAIL${RESET}]"
else
    echo -e " Ensure sshd Ciphers are configured...[${GREEN}PASS${RESET}]"
fi
client_alive_interval=$(sshd -T | grep -i '^clientaliveinterval' | awk '{print $2}')
client_alive_countmax=$(sshd -T | grep -i '^clientalivecountmax' | awk '{print $2}')
required_interval=15
required_countmax=3
if [[ -z "$client_alive_interval" || "$client_alive_interval" -lt "$required_interval" ]] || [[ -z "$client_alive_countmax" || "$client_alive_countmax" -lt "$required_countmax" ]]; then
    echo -e " Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured...[${GREEN}PASS${RESET}]"
fi
disable_forwarding=$(sshd -T | grep -i '^disableforwarding' | awk '{print $2}')
if [[ "$disable_forwarding" == "yes" ]]; then
    echo -e " Ensure sshd DisableForwarding is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd DisableForwarding is enabled...[${RED}FAIL${RESET}]"
fi
gssapi_auth=$(sshd -T | grep -i '^gssapiauthentication' | awk '{print $2}')

if [[ "$gssapi_auth" == "no" ]]; then
    echo -e " Ensure sshd GSSAPIAuthentication is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd GSSAPIAuthentication is disabled...[${RED}FAIL${RESET}]"
fi
hostbased_auth=$(sshd -T | grep -i '^hostbasedauthentication' | awk '{print $2}')
if [[ "$hostbased_auth" == "no" ]]; then
    echo -e " Ensure sshd HostbasedAuthentication is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd HostbasedAuthentication is disabled...[${RED}FAIL${RESET}]"
fi
ignore_rhosts=$(sshd -T | grep -i '^ignorerhosts' | awk '{print $2}')
if [[ "$ignore_rhosts" == "yes" ]]; then
    echo -e " Ensure sshd IgnoreRhosts is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd IgnoreRhosts is enabled...[${RED}FAIL${RESET}]"
fi
weak_algorithms=$(sshd -T | grep -Pi -- 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b')

if [[ -z "$weak_algorithms" ]]; then
    echo -e " Ensure sshd KexAlgorithms is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd KexAlgorithms is configured...[${RED}FAIL${RESET}]"
fi
login_grace_time=$(sshd -T | grep -i '^logingracetime' | awk '{print $2}')
if [[ "$login_grace_time" -ge 1 && "$login_grace_time" -le 60 ]]; then
    echo -e " Ensure sshd LoginGraceTime is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd LoginGraceTime is configured...[${RED}FAIL${RESET}]"
fi
log_level=$(sshd -T | grep -i '^loglevel' | awk '{print $2}')
if [[ "$log_level" == "INFO" || "$log_level" == "VERBOSE" ]]; then
    echo -e " Ensure sshd LogLevel is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd LogLevel is configured...[${RED}FAIL${RESET}]"
fi
weak_macs=$(sshd -T | grep -Pi -- 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b')

if [[ -z "$weak_macs" ]]; then
    echo -e " Ensure sshd MACs are configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd MACs are configured...[${RED}FAIL${RESET}]"
fi
max_auth_tries=$(sshd -T | grep -i '^maxauthtries' | awk '{print $2}')
if [[ "$max_auth_tries" -le 4 ]]; then
    echo -e " Ensure sshd MaxAuthTries is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd MaxAuthTries is configured...[${RED}FAIL${RESET}]"
fi
max_sessions=$(sshd -T | grep -i '^maxsessions' | awk '{print $2}')
if [[ "$max_sessions" -le 10 ]]; then
    echo -e " Ensure sshd MaxSessions is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd MaxSessions is configured...[${RED}FAIL${RESET}]"
fi
max_startups=$(sshd -T | grep -i '^maxstartups' | awk '{print $2}')
IFS=':' read -r start rate full <<< "$max_startups"

if [[ "$start" -le 10 && "$rate" -le 30 && "$full" -le 60 ]]; then
    echo -e " Ensure sshd MaxStartups is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd MaxStartups is configured...[${RED}FAIL${RESET}]"
fi
permit_empty=$(sshd -T | grep -i '^permitemptypasswords' | awk '{print $2}')
if [[ "$permit_empty" == "no" ]]; then
    echo -e " Ensure sshd PermitEmptyPasswords is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd PermitEmptyPasswords is disabled...[${RED}FAIL${RESET}]"
fi
permit_root=$(sshd -T | grep -i '^permitrootlogin' | awk '{print $2}')
if [[ "$permit_root" == "no" ]]; then
    echo -e " Ensure sshd PermitRootLogin is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd PermitRootLogin is disabled...[${RED}FAIL${RESET}]"
fi
permit_env=$(sshd -T | grep -i '^permituserenvironment' | awk '{print $2}')
if [[ "$permit_env" == "no" ]]; then
    echo -e " Ensure sshd PermitUserEnvironment is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd PermitUserEnvironment is disabled...[${RED}FAIL${RESET}]"
fi
usepam_val=$(sshd -T | grep -i '^usepam' | awk '{print $2}')
if [[ "$usepam_val" == "yes" ]]; then
    echo -e " Ensure sshd UsePAM is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sshd UsePAM is enabled...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing ssh server completed${RESET}"
sleep 5
printf "${BLUE}[+] Access Control${RESET}\n"
printf "╭───────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing privilege escalation${RESET}...\n"
printf "╰─..★.───────────────────────────────────────────────╯\n"
sleep 5
if dpkg-query -s sudo &>/dev/null; then
    echo -e " Ensure sudo is installed...[${GREEN}PASS${RESET}]"
elif dpkg-query -s sudo-ldap &>/dev/null; then
    echo -e " Ensure sudo-ldap is installed...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sudo or sudo-ldap is installed...[${RED}FAIL${RESET}]"
fi
if grep -rPi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers /etc/sudoers.d &>/dev/null && \
   ! grep -rPi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers /etc/sudoers.d &>/dev/null; then
    echo -e " Ensure sudo commands use pty...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sudo commands use pty...[${RED}FAIL${RESET}]"
fi
if grep -rEi '^[[:space:]]*Defaults[[:space:]]+([^#]*,)?[[:space:]]*logfile[[:space:]]*=[[:space:]]*(["'\''])?/var/log/sudo\.log(["'\''])?(,[[:space:]]*\S+)*[[:space:]]*(#.*)?$' /etc/sudoers /etc/sudoers.d &>/dev/null; then
    echo -e " Ensure sudo log file is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sudo log file is configured...[${RED}FAIL${RESET}]"
fi
if ! grep -r "^[^#].*NOPASSWD" /etc/sudoers /etc/sudoers.d &>/dev/null; then
    echo -e " Ensure sudo requires password for privilege escalation...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure sudo requires password for privilege escalation...[${RED}FAIL${RESET}]"
fi
if ! grep -r "^[^#].*!authenticate" /etc/sudoers /etc/sudoers.d &>/dev/null; then
    echo -e " Ensure re-authentication for privilege escalation is not disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure re-authentication for privilege escalation is not disabled...[${RED}FAIL${RESET}]"
fi
for file in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$file" ] || continue
    timeout=$(grep -oP "timestamp_timeout\s*=\s*\K[0-9\-]+" "$file" 2>/dev/null)
    if [ -n "$timeout" ]; then
        configured_timeout="$timeout"
        break
    fi
done
if [ -z "$configured_timeout" ]; then
    default_timeout=$(sudo -V | grep "Authentication timestamp timeout" | awk -F: '{print $2}' | awk '{print $1}' | tr -d ' ')
    if [ "$default_timeout" -le 15 ] 2>/dev/null; then
        echo -e " Ensure sudo authentication timeout is ≤ 15 minutes...${RESET}[${GREEN}PASS${RESET}]\n"
    else
        echo -e " Ensure sudo authentication timeout is ≤ 15 minutes...${RESET}[${RED}FAIL${RESET}]\n"
    fi
elif [ "$configured_timeout" -le 15 ] 2>/dev/null && [ "$configured_timeout" -ge 0 ] 2>/dev/null; then
    echo -e " Ensure sudo authentication timeout is ≤ 15 minutes...${RESET}[${GREEN}PASS${RESET}]\n"
else
    echo -e " Ensure sudo authentication timeout is ≤ 15 minutes...${RESET}[${RED}FAIL${RESET}]\n"
fi
SU_GROUP="sugroup"
if grep -Piq "^\s*auth\s+(required|requisite)\s+pam_wheel\.so\s+.*use_uid.*group=$SU_GROUP" /etc/pam.d/su; then
    if getent group "$SU_GROUP" | grep -qvE "^$SU_GROUP:x:[0-9]+:$"; then
        echo -e " Ensure access to the su command is restricted...[${RED}FAIL${RESET}]"
    else
        echo -e " Ensure access to the su command is restricted...[${GREEN}PASS${RESET}]"
    fi
else
    echo -e " Ensure access to the su command is restricted...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing privilege escalation completed${RESET}"
sleep 5
printf "${BLUE}[+] Access Control${RESET}\n"
printf "╭─────────────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Pluggable Authentication Modules${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────────────╯\n"
sleep 5
if dpkg-query -s libpam-runtime &>/dev/null; then
    pam_version=$(dpkg-query -W -f='${Version}' libpam-runtime)
    required_version="1.5.3-5"
    if dpkg --compare-versions "$pam_version" ge "$required_version"; then
        echo -e " Ensure latest version of PAM is installed...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure latest version of PAM is installed...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " Ensure latest version of PAM is installed...[${RED}FAIL${RESET}]"
fi
if dpkg-query -s libpam-modules &>/dev/null; then
    pam_mod_version=$(dpkg-query -W -f='${Version}' libpam-modules)
    required_version="1.5.3-5"

    if dpkg --compare-versions "$pam_mod_version" ge "$required_version"; then
        echo -e " Ensure libpam-modules is installed...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure libpam-modules is installed...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " Ensure libpam-modules is installed...[${RED}FAIL${RESET}]"
fi
if dpkg-query -s libpam-pwquality &>/dev/null; then
    echo -e " Ensure libpam-pwquality is installed...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure libpam-pwquality is installed...[${RED}FAIL${RESET}]"
fi
if grep -qP '\bpam_unix\.so\b' /etc/pam.d/common-{account,session,auth,password}; then
    echo -e " Ensure pam_unix module is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure pam_unix module is enabled...[${RED}FAIL${RESET}]"
fi
if grep -qP '\bpam_faillock\.so\b' /etc/pam.d/common-auth && grep -qP '\bpam_faillock\.so\b' /etc/pam.d/common-account; then
    echo -e " Ensure pam_faillock module is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure pam_faillock module is enabled...[${RED}FAIL${RESET}]"
fi
if grep -qP '\bpam_pwquality\.so\b' /etc/pam.d/common-password; then
    echo -e " Ensure pam_pwquality module is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure pam_pwquality module is enabled...[${RED}FAIL${RESET}]"
fi
if grep -qP '\bpam_pwhistory\.so\b' /etc/pam.d/common-password; then
    echo -e " Ensure pam_pwhistory module is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure pam_pwhistory module is enabled...[${RED}FAIL${RESET}]"
fi
if grep -Pq '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf; then
    echo -e " Password failed attempts lockout (deny ≤ 5)...[${GREEN}PASS${RESET}]"
else
    echo -e " Password failed attempts lockout (deny ≤ 5)...[${RED}FAIL${RESET}]"
fi
if grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' /etc/pam.d/common-auth > /dev/null; then
    echo -e " pam_faillock.so deny override (>5) found...[${RED}FAIL${RESET}]"
else
    echo -e " pam_faillock.so deny override (>5) not found...[${GREEN}PASS${RESET}]"
fi
if grep -Pq '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf; then
    echo -e " Password unlock_time set to compliant value...[${GREEN}PASS${RESET}]"
else
    echo -e " Password unlock_time not set or non-compliant...[${RED}FAIL${RESET}]"
fi
if grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?unlock_time\h*=\h*([1-9]|[1-9][0-9]|[1-8][0-9][0-9])\b' /etc/pam.d/common-auth > /dev/null; then
    echo -e " pam_faillock.so unlock_time override (<900) found...[${RED}FAIL${RESET}]"
else
    echo -e " pam_faillock.so unlock_time override (<900) not found...[${GREEN}PASS${RESET}]"
fi
difok_conf=$(grep -Psi -- '^\h*difok\h*=\h*([2-9]|[1-9][0-9]+)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
pam_difok_override=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?difok\h*=\h*[0-1]\b' /etc/pam.d/common-password 2>/dev/null)
if [[ -n "$difok_conf" && -z "$pam_difok_override" ]]; then
    echo -e " Ensure password number of changed characters (difok) is set to 2 or more...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password number of changed characters (difok) is set to 2 or more...[${RED}FAIL${RESET}]"
fi
minlen_conf=$(grep -Psi -- '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
pam_minlen_override=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?minlen\h*=\h*([0-9]|1[0-3])\b' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null)

if [[ -n "$minlen_conf" && -z "$pam_minlen_override" ]]; then
    echo -e " Ensure minimum password length (minlen) is set to 14 or more...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure minimum password length (minlen) is set to 14 or more...[${RED}FAIL${RESET}]"
fi
pwquality_conf_check=$(grep -Psi -- '^\h*(minclass|[dulo]credit)\h*=' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
pam_override_check=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?(minclass=\d*|[dulo]credit=-?\d*)\b' /etc/pam.d/common-password 2>/dev/null)

if [[ -n "$pwquality_conf_check" && -z "$pam_override_check" ]]; then
    echo -e " Ensure password complexity is configured properly...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password complexity is configured properly...[${RED}FAIL${RESET}]"
fi
maxrepeat_conf=$(grep -Psi -- '^\h*maxrepeat\h*=\h*[1-3]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
pam_maxrepeat_override=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?maxrepeat\h*=\h*(0|[4-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null)
if [[ -n "$maxrepeat_conf" && -z "$pam_maxrepeat_override" ]]; then
    echo -e " Ensure password same consecutive characters (maxrepeat) is set to 3 or less...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password same consecutive characters (maxrepeat) is set to 3 or less...[${RED}FAIL${RESET}]"
fi
maxsequence_conf=$(grep -Psi -- '^\h*maxsequence\h*=\h*[1-3]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
pam_maxsequence_override=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?maxsequence\h*=\h*(0|[4-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null)

if [[ -n "$maxsequence_conf" && -z "$pam_maxsequence_override" ]]; then
    echo -e " Ensure password maximum sequential characters (maxsequence) is set to 3 or less...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password maximum sequential characters (maxsequence) is set to 3 or less...[${RED}FAIL${RESET}]"
fi
dictcheck_conf=$(grep -Psi -- '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
pam_dictcheck_override=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?dictcheck\h*=\h*0\b' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null)

if [[ -z "$dictcheck_conf" && -z "$pam_dictcheck_override" ]]; then
    echo -e " Ensure password dictionary check (dictcheck) is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password dictionary check (dictcheck) is enabled...[${RED}FAIL${RESET}]"
fi
enforcing_conf=$(grep -Psi -- '^\h*enforcing\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
pam_enforcing_override=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null)

if [[ -z "$enforcing_conf" && -z "$pam_enforcing_override" ]]; then
    echo -e " Ensure password quality enforcement (enforcing) is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password quality enforcement (enforcing) is enabled...[${RED}FAIL${RESET}]"
fi
enforce_for_root_conf=$(grep -Psi -- '^\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)

if [[ -n "$enforce_for_root_conf" ]]; then
    echo -e " Ensure password quality enforcement for root is enabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password quality enforcement for root is enabled...[${RED}FAIL${RESET}]"
fi
remember_setting=$(grep -Psi -- '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=\d+\b' /etc/pam.d/common-password 2>/dev/null)

if [[ -n "$remember_setting" ]]; then
    remember_value=$(echo "$remember_setting" | grep -oP 'remember=\K\d+')
    if [[ "$remember_value" -ge 24 ]]; then
        echo -e " Ensure password history remember is configured (>=24)...[${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure password history remember is configured (>=24)...[${RED}FAIL${RESET}]"
    fi
else
    echo -e " Ensure password history remember is configured (>=24)...[${RED}FAIL${RESET}]"
fi
root_enforce_check=$(grep -Psi -- '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?enforce_for_root\b' /etc/pam.d/common-password 2>/dev/null)

if [[ -n "$root_enforce_check" ]]; then
    echo -e " Ensure password history is enforced for root user...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password history is enforced for root user...[${RED}FAIL${RESET}]"
fi
use_authtok_check=$(grep -Psi -- '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b' /etc/pam.d/common-password 2>/dev/null)

if [[ -n "$use_authtok_check" ]]; then
    echo -e " Ensure pam_pwhistory includes use_authtok...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure pam_pwhistory includes use_authtok...[${RED}FAIL${RESET}]"
fi
pam_unix_nullok_check=$(grep -PHs -- '^\h*[^#\r\n]*\h+pam_unix\.so\b' /etc/pam.d/common-{password,auth,account,session,session-noninteractive} 2>/dev/null | grep -P '\bnullok\b')
if [[ -z "$pam_unix_nullok_check" ]]; then
    echo -e " Ensure pam_unix.so does not include nullok... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure pam_unix.so does not include nullok... [${RED}FAIL${RESET}]"
fi
pam_unix_remember_check=$(grep -PH -- '^\h*[^#\n\r]+\h+pam_unix\.so\b' /etc/pam.d/common-{password,auth,account,session,session-noninteractive} 2>/dev/null | grep -P '\bremember=\d+\b')

if [[ -z "$pam_unix_remember_check" ]]; then
    echo -e " Ensure pam_unix.so does not include remember=...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure pam_unix.so does not include remember=...[${RED}FAIL${RESET}]"
    echo "$pam_unix_remember_check"
fi
pam_unix_hash_check=$(grep -PH -- '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?(sha512|yescrypt)\b' /etc/pam.d/common-password 2>/dev/null)

if [[ -n "$pam_unix_hash_check" ]]; then
    echo -e " Ensure pam_unix.so uses a strong hashing algorithm (sha512 or yescrypt)...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure pam_unix.so uses a strong hashing algorithm (sha512 or yescrypt)...[${RED}FAIL${RESET}]"
fi
pam_unix_use_authtok_check=$(grep -PH -- '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b' /etc/pam.d/common-password 2>/dev/null)

if [[ -n "$pam_unix_use_authtok_check" ]]; then
    echo -e " Ensure pam_unix.so includes use_authtok in password stack...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure pam_unix.so includes use_authtok in password stack...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing Pluggable Authentication Modules completed${RESET}"
sleep 5
printf "${BLUE}[+] User Accounts and Environment ${RESET}\n"
printf "╭─────────────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing shadow password suite parameters ${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────────────────╯\n"
sleep 5
pass_max_days_login_defs=$(grep -Pi -- '^\h*PASS_MAX_DAYS\h+\d+\b' /etc/login.defs)

if echo "$pass_max_days_login_defs" | grep -Pq '\b([1-9][0-9]{0,2}|1000)\b'; then
    echo -e " Ensure password expiration is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password expiration is configured...[${RED}FAIL${RESET}]"
fi
awk -F: '($2~/^\$.+\$/) {
    if($5 > 365 || $5 < 1)
        printf " User: %s has PASS_MAX_DAYS set to %s...[FAIL]\n", $1, $5
}' /etc/shadow
pass_min_days_login_defs=$(grep -Pi -- '^\h*PASS_MIN_DAYS\h+\d+\b' /etc/login.defs)

if echo "$pass_min_days_login_defs" | grep -Pq '\b([1-9][0-9]*)\b'; then
    echo -e " Ensure minimum password days is configured ...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure minimum password days is configured ...[${RED}FAIL${RESET}]"
fi
awk -F: '($2~/^\$.+\$/) {
    if($4 < 1)
        printf " User: %s has PASS_MIN_DAYS set to %s...[FAIL]\n", $1, $4
}' /etc/shadow
pass_warn_age_login_defs=$(grep -Pi -- '^\h*PASS_WARN_AGE\h+\d+\b' /etc/login.defs)
if echo "$pass_warn_age_login_defs" | grep -Pq '\b([7-9]|[1-9][0-9]+)\b'; then
    echo -e " Ensure password expiration warning days is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure password expiration warning days is configured...[${RED}FAIL${RESET}]"
fi
awk -F: '($2~/^\$.+\$/) {
    if($6 < 7)
        printf " User: %s has PASS_WARN_AGE set to %s...[FAIL]\n", $1, $6
}' /etc/shadow
encrypt_method=$(grep -Pi -- '^\h*ENCRYPT_METHOD\h+(sha512|yescrypt)\b' /etc/login.defs)
if [[ -n "$encrypt_method" ]]; then
    echo -e " Ensure strong password hashing algorithm is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure strong password hashing algorithm is configured...[${RED}FAIL${RESET}]"
fi
inactive_default=$(useradd -D | grep -Po 'INACTIVE=\K\S+')
if [[ "$inactive_default" -le 45 && "$inactive_default" -ge 0 ]]; then
    echo -e " Ensure inactive password lock is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure inactive password lock is configured...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing shadow password suite parameters completed${RESET}"
sleep 5
printf "╭────────────────────────────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing root and system accounts and environment ${RESET}...\n"
printf "╰─..★.────────────────────────────────────────────────────────────────────╯\n"
sleep 5
if [ "$(awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v '^root$')" ]; then
    echo -e " Ensure only 'root' has UID 0...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure only 'root' has UID 0...[${GREEN}PASS${RESET}]"
fi
if [ "$(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)$/ && $4 == 0 && $1 != "root") { print $1 }' /etc/passwd)" ]; then
    echo -e " Ensure only 'root' has GID 0...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure only 'root' has GID 0...[${GREEN}PASS${RESET}]"
fi
if [ "$(awk -F: '($1 != "root" && $3 == 0) { print $1 }' /etc/group)" ]; then
    echo -e " Ensure only 'root' group has GID 0...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure only 'root' group has GID 0...[${GREEN}PASS${RESET}]"
fi
status=$(passwd -S root | awk '{print $2}')
if [[ "$status" == "P" || "$status" == "L" ]]; then
    echo -e " Ensure root account access is controlled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure root account access is controlled...[${RED}FAIL${RESET}]"
fi
l_output2=""
l_pmask="0022"
l_maxperm="$(printf '%o' $(( 0777 & ~$l_pmask )))"
l_root_path="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
unset a_path_loc && IFS=":" read -ra a_path_loc <<< "$l_root_path"
grep -q "::" <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains an empty directory (::)"
grep -Pq ":\h*$" <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains a trailing (:) "
grep -Pq '(\h+|:)\.(:|\h*$)' <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains current working directory (.)"
for l_path in "${a_path_loc[@]}"; do
    if [ -d "$l_path" ]; then
        read -r l_fmode l_fown <<< "$(stat -Lc '%#a %U' "$l_path")"
        [ "$l_fown" != "root" ] && l_output2="$l_output2\n - Directory \"$l_path\" is owned by \"$l_fown\"; should be owned by \"root\""
        [ $(( l_fmode & l_pmask )) -gt 0 ] && l_output2="$l_output2\n - Directory \"$l_path\" permissions are \"$l_fmode\"; should be \"$l_maxperm\" or more restrictive"
    else
        case "$l_path" in
            /snap/bin|/usr/games|/usr/local/games) ;;
            *) l_output2="$l_output2\n - \"$l_path\" is not a directory" ;;
        esac
    fi
done
if [ -z "$l_output2" ]; then
    echo -e " Ensure root path integrity...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure root path integrity...[${RED}FAIL${RESET}]"
    echo -e "$l_output2"
fi
if grep -Psiq -- '^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc; then
    echo -e " Ensure root user umask is configured securely...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure root user umask is configured securely...[${GREEN}PASS${RESET}]"
fi
valid_shells="$(awk -F/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells | paste -sd '|' -)"
if awk -v pat="^($valid_shells)$" -F: '
  ($1 !~ /^(root|halt|sync|shutdown|nfsnobody)$/ &&
  ($3 < '"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' || $3 == 65534) &&
  $NF ~ pat) { exit 1 }' /etc/passwd; then
    echo -e " Ensure system accounts do not have a valid login shell...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure system accounts do not have a valid login shell...[${RED}FAIL${RESET}]"
fi
valid_shells="^($(awk -F/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells | paste -sd '|' -))$"
locked_status=0
while IFS= read -r user; do
    user_status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
    if [[ "$user_status" != "L" ]]; then
        locked_status=1
        echo -e " - User \"$user\" without valid shell is not locked...[${RED}FAIL${RESET}]"
    fi
done < <(awk -v pat="$valid_shells" -F: '
($1 != "root" && $(NF) !~ pat) { print $1 }' /etc/passwd)
if [[ $locked_status -eq 0 ]]; then
    echo -e " Ensure accounts without a valid login shell are locked...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure accounts without a valid login shell are locked...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing root and system accounts and environment completed${RESET}"
sleep 5
printf "${BLUE}[+] User Accounts and Environment ${RESET}\n"
printf "╭────────────────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing user default environment ${RESET}...\n"
printf "╰─..★.────────────────────────────────────────────────────────╯\n"
sleep 5
if grep -Ps '^\h*([^#\n\r]+)?/nologin\b' /etc/shells >/dev/null; then
    echo -e " Ensure nologin is not listed in /etc/shells...[${RED}FAIL${RESET}]"
else
    echo -e " Ensure nologin is not listed in /etc/shells...[${GREEN}PASS${RESET}]"
fi
output1=""
output2=""
[ -f /etc/bashrc ] && BRC="/etc/bashrc"
for f in "$BRC" /etc/profile /etc/profile.d/*.sh; do
    if [ -f "$f" ]; then
        if grep -Pq '^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' "$f" && \
           grep -Pq '^\s*([^#]+;\s*)?readonly\s+TMOUT' "$f" && \
           grep -Pq '^\s*([^#]+;\s*)?export\s+TMOUT' "$f"; then
            output1="$f"
        fi
    fi
done
if grep -Pq '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh "$BRC" 2>/dev/null; then
    output2=$(grep -Ps '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh "$BRC" 2>/dev/null)
fi
if [[ -n "$output1" && -z "$output2" ]]; then
    echo -e " Ensure default user shell timeout is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure default user shell timeout is configured...[${RED}FAIL${RESET}]"
fi
output1=""
output2=""
[ -f /etc/bashrc ] && BRC="/etc/bashrc"
for f in "$BRC" /etc/profile /etc/profile.d/*.sh; do
    [ -f "$f" ] || continue
    if grep -Pq '^\s*umask\s+0?027\b' "$f"; then
        output1="$f"
    fi
done
for f in "$BRC" /etc/profile /etc/profile.d/*.sh; do
    [ -f "$f" ] || continue
    if grep -Pq '^\s*umask\s+(0[0-9]{3}|[0-9]{2,3})\b' "$f" && \
       ! grep -Pq '^\s*umask\s+0?027\b' "$f"; then
        output2="$f"
    fi
done
if [[ -n "$output1" && -z "$output2" ]]; then
    echo -e " Ensure default user umask is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure default user umask is configured...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing user default environment completed${RESET}"
sleep 5
printf "${BLUE}[+] Logging and Auditing ${RESET}\n"
printf "╭──────────────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing systemd-journald service  ${RESET}...\n"
printf "╰─..★.──────────────────────────────────────────────────────╯\n"
sleep 5
status_enabled=$(systemctl is-enabled systemd-journald.service 2>/dev/null)
status_active=$(systemctl is-active systemd-journald.service 2>/dev/null)
if [[ "$status_enabled" == "static" && "$status_active" == "active" ]]; then
    echo -e " Ensure journald service is enabled and active...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure journald service is enabled and active...[${RED}FAIL${RESET}]"
    printf "   - Status enabled: %s\n" "$status_enabled"
    printf "   - Status active : %s\n" "$status_active"
fi
PASS=true
if [[ -d /var/log/journal ]]; then
    while IFS= read -r file; do
        mode=$(stat -c %a "$file")
        if (( 10#$mode > 640 )); then
            PASS=false
        fi
    done < <(find /var/log/journal -type f)
fi
for dir in /run /var/lib/systemd; do
    if [[ -d "$dir" ]]; then
        mode=$(stat -c %a "$dir")
        if (( 10#$mode > 755 )); then
            PASS=false
        fi
    fi
done
if $PASS; then
    echo -e " Ensure journald log file access is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure journald log file access is configured...[${RED}FAIL${RESET}]"
fi
if grep -Prsq '^\s*(SystemMaxUse|SystemKeepFree|RuntimeMaxUse|RuntimeKeepFree|MaxFileSec)=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null; then
     echo -e " Ensure journald log file rotation is configured...[${GREEN}PASS${RESET}]"
else
     echo -e " Ensure journald log file rotation is configured...[${RED}FAIL${RESET}]"
fi
if systemctl is-active --quiet rsyslog && systemctl is-active --quiet systemd-journald; then
    echo -e " Ensure only one logging system is in use...[${RED}FAIL${RESET}]"
elif systemctl is-active --quiet rsyslog; then
    echo -e " Ensure only one logging system is in use...[${GREEN}PASS${RESET}] (rsyslog is active)"
elif systemctl is-active --quiet systemd-journald; then
    echo -e " Ensure only one logging system is in use...[${GREEN}PASS${RESET}] (journald is active)"
else
    echo -e " Ensure only one logging system is in use...[${RED}FAIL${RESET}] (No active logging)"
fi
echo -e "➽ ${GREEN}Auditing systemd-journald service completed${RESET}"
sleep 5
printf "${BLUE}[+] Logging and Auditing ${RESET}\n"
printf "╭────────────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing systemd-journal-remote  ${RESET}...\n"
printf "╰─..★.────────────────────────────────────────────────────╯\n"
sleep 5
if dpkg-query -W -f='${Status}' systemd-journal-remote 2>/dev/null | grep -q "install ok installed"; then
    echo -e " Ensure systemd-journal-remote is installed...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure systemd-journal-remote is installed...[${RED}FAIL${RESET}]"
fi
required_params=("ServerCertificateFile" "ServerKeyFile" "TrustedCertificateFile" "URL")
conf_files=$(systemd-analyze cat-config systemd/journal-upload.conf | tac | grep -Po '^\s*#\s*/[^#\n\r\s]+\.conf\b' | tr -d '#' | tr -d ' ')
missing=0
for param in "${required_params[@]}"; do
    found=0
    while read -r file; do
        if grep -Pq "^\s*${param}=" "$file" 2>/dev/null; then
            found=1
            break
        fi
    done <<< "$conf_files"
    [ "$found" -eq 0 ] && missing=1 && break
done
if [ "$missing" -eq 0 ]; then
    echo -e " Ensure systemd-journal-upload authentication is configured...${RESET}[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure systemd-journal-upload authentication is configured...${RESET}[${RED}FAIL${RESET}]"
fi
if systemctl is-enabled systemd-journal-upload.service >/dev/null 2>&1 && \
   systemctl is-active systemd-journal-upload.service >/dev/null 2>&1; then
    echo -e " Ensure systemd-journal-upload is enabled and active...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure systemd-journal-upload is enabled and active...[${RED}FAIL${RESET}]"
fi
if systemd-analyze cat-config systemd/journald.conf | grep -Pq '^\s*ForwardToSyslog\s*=\s*no\s*$'; then
    echo -e " Ensure journald ForwardToSyslog is disabled...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure journald ForwardToSyslog is disabled...[${RED}FAIL${RESET}]"
fi
if systemd-analyze cat-config systemd/journald.conf | grep -Pq '^\s*Compress\s*=\s*yes\s*$'; then
    echo -e " Ensure journald Compress is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure journald Compress is configured...[${RED}FAIL${RESET}]"
fi
if systemd-analyze cat-config systemd/journald.conf | grep -Pq '^\s*Storage\s*=\s*persistent\s*$'; then
    echo -e " Ensure journald Storage is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure journald Storage is configured...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing systemd-journal-remote completed${RESET}"
sleep 5
printf "${BLUE}[+] Logging and Auditing ${RESET}\n"
printf "╭─────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Logfiles  ${RESET}...\n"
printf "╰─..★.─────────────────────────────────────────╯\n"
sleep 5
if find /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) | grep -q .; then
    echo -e " Ensure access to all logfiles is configured... [${RED}FAIL${RESET}]"
else
    echo -e " Ensure access to all logfiles is configured... [${GREEN}PASS${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing Logfiles completed${RESET}"
sleep 5
printf "${BLUE}[+] Logging and Auditing ${RESET}\n"
printf "╭────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing auditd Service ${RESET}...\n"
printf "╰─..★.────────────────────────────────────────────╯\n"
sleep 5 
if dpkg-query -s auditd &>/dev/null && dpkg-query -s audispd-plugins &>/dev/null; then
    echo -e " Ensure auditd and audispd-plugins are installed... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure auditd and audispd-plugins are installed... [${RED}FAIL${RESET}]"
fi
if systemctl is-enabled auditd 2>/dev/null | grep -q '^enabled' && systemctl is-active auditd 2>/dev/null | grep -q '^active'; then
    echo -e " Ensure auditd service is enabled and active... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure auditd service is enabled and active... [${RED}FAIL${RESET}]"
fi
if find /boot -type f -name 'grub.cfg' -exec grep -Ph '^\h*linux' {} + | grep -vq 'audit=1'; then
    echo -e " Ensure auditing at boot is enabled (audit=1)... [${RED}FAIL${RESET}]"
else
    echo -e " Ensure auditing at boot is enabled (audit=1)... [${GREEN}PASS${RESET}]"
fi
if sudo grep -Ph '^\h*linux' /boot/grub/grub.cfg 2>/dev/null | grep -Po 'audit_backlog_limit=\K\d+' | grep -qvE '^(8192|[89][0-9]{3,}|[1-9][0-9]{4,})'; then
    echo -e " Ensure audit_backlog_limit is set to 8192 or higher... [${RED}FAIL${RESET}]"
elif ! sudo grep -Ph '^\h*linux' /boot/grub/grub.cfg 2>/dev/null | grep -q 'audit_backlog_limit='; then
    echo -e " Ensure audit_backlog_limit is set to 8192 or higher... [${RED}FAIL${RESET}]"
else
    echo -e " Ensure audit_backlog_limit is set to 8192 or higher... [${GREEN}PASS${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing auditd Service completed${RESET}"
sleep 5
printf "${BLUE}[+] Logging and Auditing ${RESET}\n"
printf "╭────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing Data Retention ${RESET}...\n"
printf "╰─..★.────────────────────────────────────────────╯\n"
sleep 5 
if grep -Pq '^\s*max_log_file\s*=\s*\d+\b' /etc/audit/auditd.conf; then
    echo -e " Ensure audit log storage size is configured...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure audit log storage size is configured...[${RED}FAIL${RESET}]"
fi
if grep -Pq '^\s*max_log_file_action\s*=\s*keep_logs\b' /etc/audit/auditd.conf; then
    echo -e " Ensure audit logs are not automatically deleted...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure audit logs are not automatically deleted...[${RED}FAIL${RESET}]"
fi
dfull=$(grep -Pi '^\s*disk_full_action\s*=\s*(halt|single)\b' /etc/audit/auditd.conf)
derr=$(grep -Pi '^\s*disk_error_action\s*=\s*(syslog|single|halt)\b' /etc/audit/auditd.conf)

if [[ -n "$dfull" && -n "$derr" ]]; then
    echo -e " Ensure system is disabled when audit logs are full...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure system is disabled when audit logs are full...[${RED}FAIL${RESET}]"
fi
low=$(grep -P '^\s*space_left_action\s*=\s*(email|exec|single|halt)\b' /etc/audit/auditd.conf)
admin=$(grep -P '^\s*admin_space_left_action\s*=\s*(single|halt)\b' /etc/audit/auditd.conf)
if [[ -n "$low" && -n "$admin" ]]; then
    echo -e " Ensure system warns when audit logs are low on space...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure system warns when audit logs are low on space...[${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing Data Retention completed${RESET}"
sleep 5
printf "${BLUE}[+] Logging and Auditing ${RESET}\n"
printf "╭────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing auditd Rules ${RESET}...\n"
printf "╰─..★.────────────────────────────────────────────╯\n"
sleep 5
on_disk=$(awk '/^ *-w/ && /\/etc\/sudoers/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c 'scope')
running=$(auditctl -l 2>/dev/null | awk '/^ *-w/ && /\/etc\/sudoers/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' | grep -c 'scope')
if [[ "$on_disk" -ge 2 && "$running" -ge 2 ]]; then
    echo -e " Ensure changes to system administration scope...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure changes to system administration scope...[${RED}FAIL${RESET}]"
fi
on_disk=$(awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && (/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && (/ -C *euid!=uid/ || / -C *uid!=euid/) && / -S *execve/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c 'user_emulation')
running=$(auditctl -l 2>/dev/null | awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && (/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && (/ -C *euid!=uid/ || / -C *uid!=euid/) && / -S *execve/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' | grep -c 'user_emulation')
if [[ "$on_disk" -ge 2 && "$running" -ge 2 ]]; then
    echo -e " Ensure actions as another user are always logged...[${GREEN}PASS${RESET}]"
else
    echo -e " Ensure actions as another user are always logged...[${RED}FAIL${RESET}]"
fi
SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* 2>/dev/null | sed -e 's/.*logfile=//;s/,.*//' -e 's/"//g')
if [[ -n "$SUDO_LOG_FILE" ]]; then
    on_disk=$(awk -v file="$SUDO_LOG_FILE" '/^ *-w/ && $0 ~ file && /-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c "$SUDO_LOG_FILE")
    running=$(auditctl -l 2>/dev/null | awk -v file="$SUDO_LOG_FILE" '/^ *-w/ && $0 ~ file && /-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' | grep -c "$SUDO_LOG_FILE")

    if [[ "$on_disk" -ge 1 && "$running" -ge 1 ]]; then
        echo -e " Ensure events that modify the sudo log file are collected...[$GREEN"PASS"$RESET]"
    else
        echo -e " Ensure events that modify the sudo log file are collected...[$RED"FAIL"$RESET]"
    fi
else
    echo -e " Ensure events that modify the sudo log file are collected...[$YELLOW"SKIPPED"$RESET] (sudo log file not configured)"
fi
# on_disk=$(awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && / -S/ && (/adjtimex/ || /settimeofday/ || /clock_settime/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c 'time-change')
# on_disk_localtime=$(awk '/^ *-w/ && /\/etc\/localtime/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c 'time-change')
# running=$(auditctl -l 2>/dev/null | awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && / -S/ && (/adjtimex/ || /settimeofday/ || /clock_settime/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' | grep -c 'time-change')
# running_localtime=$(auditctl -l 2>/dev/null | awk '/^ *-w/ && /\/etc\/localtime/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' | grep -c 'time-change')
# if [[ "$on_disk" -ge 4 && "$on_disk_localtime" -ge 1 && "$running" -ge 4 && "$running_localtime" -ge 1 ]]; then
#     echo -e " Ensure events that modify date and time information are collected...[$GREEN"PASS"$RESET]"
# else
#     echo -e " Ensure events that modify date and time information are collected...[$RED"FAIL"$RESET]"
# fi
# on_disk_syscalls=$(awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && / -S/ && (/sethostname/ || /setdomainname/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c 'system-locale' 2>/dev/null)
# on_disk_files=$(awk '/^ *-w/ && (/\/etc\/issue/ || /\/etc\/issue.net/ || /\/etc\/hosts/ || /\/etc\/networks/ || /\/etc\/network/ || /\/etc\/netplan/) && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c 'system-locale' 2>/dev/null)
# running_syscalls=$(auditctl -l 2>/dev/null | awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && / -S/ && (/sethostname/ || /setdomainname/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' 2>/dev/null | grep -c 'system-locale' 2>/dev/null)
# running_files=$(auditctl -l 2>/dev/null | awk '/^ *-w/ && (/\/etc\/issue/ || /\/etc\/issue.net/ || /\/etc\/hosts/ || /\/etc\/networks/ || /\/etc\/network/ || /\/etc\/netplan/) && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/' 2>/dev/null | grep -c 'system-locale' 2>/dev/null)
# if [[ "$on_disk_syscalls" -ge 2 && "$on_disk_files" -ge 7 && "$running_syscalls" -ge 2 && "$running_files" -ge 7 ]]; then
#     echo -e " Ensure events that modify the system's network environment are collected...[${GREEN}PASS${RESET}]"
# else
#     echo -e " Ensure events that modify the system's network environment are collected...[${RED}FAIL${RESET}]"
# fi
on_disk=$(awk '/^ *-w/ && (/\/var\/log\/lastlog/ || /\/var\/run\/faillock/) && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c '/var/.*logins')
running=$(auditctl -l 2>/dev/null | awk '/^ *-w/ && (/\/var\/log\/lastlog/ || /\/var\/run\/faillock/) && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' | grep -c '/var/.*logins')
if [[ "$on_disk" -ge 2 && "$running" -ge 2 ]]; then
    echo -e " Ensure login and logout events are collected... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure login and logout events are collected... [${RED}FAIL${RESET}]"
fi
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
if [[ -z "$UID_MIN" ]]; then
    echo -e " Ensure file deletion events are collected... [${RED}FAIL${RESET}] (UID_MIN unset)"
    exit 1
fi
on_disk=$(awk -v u="$UID_MIN" '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && (/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && / -F *auid>=/ && / -S/ && (/unlink/ || /unlinkat/ || /rename/ || /renameat/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c delete)
running=$(auditctl -l 2>/dev/null | awk -v u="$UID_MIN" '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && (/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && / -F *auid>=/ && / -S/ && (/unlink/ || /unlinkat/ || /rename/ || /renameat/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' | grep -c delete)
if [[ "$on_disk" -ge 2 && "$running" -ge 2 ]]; then
    echo -e " Ensure file deletion events are collected... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure file deletion events are collected... [${RED}FAIL${RESET}]"
fi
on_disk=$(awk '/^ *-w/ && (/\/etc\/apparmor/ || /\/etc\/apparmor\.d/) && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>/dev/null | grep -c 'MAC-policy')
running=$(auditctl -l 2>/dev/null | awk '/^ *-w/ && (/\/etc\/apparmor/ || /\/etc\/apparmor\.d/) && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' | grep -c 'MAC-policy')
if [[ "$on_disk" -ge 2 && "$running" -ge 2 ]]; then
    echo -e " Ensure MAC policy modifications are audited... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure MAC policy modifications are audited... [${RED}FAIL${RESET}]"
fi
# UID_MIN=$(awk '/^\s*UID_MIN/ {print $2}' /etc/login.defs)
# on_disk=$(awk "/-a always,exit/ && /-F path=\/usr\/bin\/chcon/ && /-F perm=x/ && /-F auid>=$UID_MIN/ && (/auid!=unset/ || /auid!=-1/ || /auid!=4294967295/) && /-k perm_chng/" /etc/audit/rules.d/*.rules 2>/dev/null | wc -l)
# running=$(auditctl -l 2>/dev/null | awk "/-a always,exit/ && /-F path=\/usr\/bin\/chcon/ && /-F perm=x/ && /-F auid>=$UID_MIN/ && (/auid!=unset/ || /auid!=-1/ || /auid!=4294967295/) && /-k perm_chng/" | wc -l)
# if [[ $on_disk -ge 1 && $running -ge 1 ]]; then
#     echo -e " Monitor 'chcon' command usage... [${GREEN}PASS${RESET}]"
# else
#     echo -e " Monitor 'chcon' command usage... [${RED}FAIL${RESET}]"
# fi
if grep -Pq '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules 2>/dev/null; then
    echo -e " Ensure the audit configuration is immutable... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure the audit configuration is immutable... [${RED}FAIL${RESET}]"
fi
if augenrules --check 2>/dev/null | grep -q "No change"; then
    echo -e " Audit config on disk matches running config... [${GREEN}PASS${RESET}]"
else
    echo -e " Audit config mismatch between disk and runtime... [${RED}FAIL${RESET}]"
fi
echo -e "➽ ${GREEN}Auditing auditd Rules completed${RESET}"
sleep 5
printf "${BLUE}[+] Logging and Auditing ${RESET}\n"
printf "╭──────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing auditd File Access${RESET}...\n"
printf "╰─..★.──────────────────────────────────────────────╯\n"
sleep 5
conf="/etc/audit/auditd.conf"
[ -f "$conf" ] && dir="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' "$conf" | xargs)")" && \
find "$dir" -maxdepth 1 -type f -perm /0137 | grep -q . && \
echo -e " Ensure audit log files mode is configured... [${RED}FAIL${RESET}]" || \
echo -e " Ensure audit log files mode is configured... [${GREEN}PASS${RESET}]"
conf="/etc/audit/auditd.conf"
[ -f "$conf" ] && dir="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' "$conf" | xargs)")" && \
find "$dir" -maxdepth 1 -type f ! -user root | grep -q . && \
echo -e " Audit log files not owned by root... [${RED}FAIL${RESET}]" || \
echo -e " Audit log file ownership OK (owned by root)... [${GREEN}PASS${RESET}]"
conf="/etc/audit/auditd.conf"
if grep -Piq '^\s*log_group\s*=\s*\S+' "$conf" && \
   ! grep -Piq '^\s*log_group\s*=\s*(adm|root)\b' "$conf"; then
    echo -e " log_group is not set to 'adm' or 'root'... [${RED}FAIL${RESET}]"
else
    echo -e " log_group is set correctly... [${GREEN}PASS${RESET}]"
fi
dir="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' "$conf" | xargs)")"
find "$dir" -type f ! -group root ! -group adm | grep -q . && \
echo -e " Audit log files not group-owned by root or adm... [${RED}FAIL${RESET}]" || \
echo -e " Audit log files group-owned by root or adm... [${GREEN}PASS${RESET}]"
conf="/etc/audit/auditd.conf"
mask=$((027))
if [ -f "$conf" ]; then
  dir=$(dirname "$(awk -F= '/^\s*log_file\s*/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' "$conf")")
  [ -d "$dir" ] && mode=$(stat -c '%a' "$dir") && \
  (( (8#$mode & mask) != 0 )) && \
    echo "Audit log dir '$dir' too permissive (mode: $mode)... [FAIL]" || \
    echo "Audit log dir permissions OK (mode: $mode)... [PASS]"
else
  echo "Config file '$conf' not found."
fi
perm_mask="0137"
max_perm="$(printf '%o' $((0777 & ~$perm_mask)))"
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -perm /"$perm_mask" | grep -q . && \
echo -e " Audit config files too permissive (should be ≤ $max_perm)... [${RED}FAIL${RESET}]" || \
echo -e " Audit config file permissions OK (≤ $max_perm)... [${GREEN}PASS${RESET}]"
tools=(/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules)
for tool in "${tools[@]}"; do
  [ -f "$tool" ] && mode=$(stat -Lc '%a' "$tool") && [ "$mode" -gt 755 ] && \
  echo -e " Audit tool '$tool' too permissive (mode: $mode)... [${RED}FAIL${RESET}]" && exit 1
done
echo -e " Audit tool permissions OK (≤ 755)... [${GREEN}PASS${RESET}]"
echo -e "➽ ${GREEN}Auditing auditd file access completed${RESET}"
sleep 5
printf "${BLUE}[+] System Maintenance ${RESET}\n"
printf "╭────────────────────────────────────────────────────.★..─╮\n"
printf " • ${GREEN}Auditing System File Permissions${RESET}...\n"
printf "╰─..★.────────────────────────────────────────────────────╯\n"
sleep 5
perm="$(stat -Lc '%a' /etc/passwd)"
owner="$(stat -Lc '%u' /etc/passwd)"
group="$(stat -Lc '%g' /etc/passwd)"
if [[ "$perm" -le 644 && "$owner" -eq 0 && "$group" -eq 0 ]]; then
    echo -e " Ensure permissions on /etc/passwd are configured... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure permissions on /etc/passwd are configured... [${RED}FAIL${RESET}]"
fi
perm=$(stat -Lc "%a" /etc/group 2>/dev/null)
owner=$(stat -Lc "%u" /etc/group 2>/dev/null)
group=$(stat -Lc "%g" /etc/group 2>/dev/null)
if [[ "$perm" -le 644 && "$owner" -eq 0 && "$group" -eq 0 ]]; then
    echo -e " Ensure permissions on /etc/group are configured... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure permissions on /etc/group are configured... [${RED}FAIL${RESET}]"
fi
perm=$(stat -Lc "%a" /etc/shadow 2>/dev/null)
owner=$(stat -Lc "%u" /etc/shadow 2>/dev/null)
group=$(stat -Lc "%g" /etc/shadow 2>/dev/null)
if [[ "$perm" -le 640 && "$owner" -eq 0 && ( "$group" -eq 0 || "$group" -eq 42 ) ]]; then
    echo -e " Ensure permissions on /etc/shadow are configured... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure permissions on /etc/shadow are configured... [${RED}FAIL${RESET}]"
fi
perm=$(stat -Lc "%a" /etc/gshadow 2>/dev/null)
owner=$(stat -Lc "%u" /etc/gshadow 2>/dev/null)
group=$(stat -Lc "%g" /etc/gshadow 2>/dev/null)
if [[ "$perm" -le 640 && "$owner" -eq 0 && ( "$group" -eq 0 || "$group" -eq 42 ) ]]; then
    echo -e " Ensure permissions on /etc/gshadow are configured... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure permissions on /etc/gshadow are configured... [${RED}FAIL${RESET}]"
fi
perm=$(stat -Lc "%a" /etc/shells 2>/dev/null)
owner=$(stat -Lc "%u" /etc/shells 2>/dev/null)
group=$(stat -Lc "%g" /etc/shells 2>/dev/null)
if [[ "$perm" -le 644 && "$owner" -eq 0 && "$group" -eq 0 ]]; then
    echo -e " Ensure permissions on /etc/shells are configured... [${GREEN}PASS${RESET}]"
else
    echo -e " Ensure permissions on /etc/shells are configured... [${RED}FAIL${RESET}]"
fi
if [ -e "/etc/security/opasswd" ]; then
    perm=$(stat -Lc '%a' /etc/security/opasswd)
    owner=$(stat -Lc '%u' /etc/security/opasswd)
    group=$(stat -Lc '%g' /etc/security/opasswd)
    if [[ "$perm" -le 600 && "$owner" -eq 0 && "$group" -eq 0 ]]; then
        echo -e " Ensure permissions on /etc/security/opasswd are configured... [${GREEN}PASS${RESET}]"
    else
        echo -e " Ensure permissions on /etc/security/opasswd are configured... [${RED}FAIL${RESET}]"
    fi
fi

# Strip ANSI color codes before counting
stripped_output=$(sed 's/\x1B\[[0-9;]*[JKmsu]//g' "$audit_output")

pass_count=$(printf "%s" "$stripped_output" | grep -c "\[PASS\]")
fail_count=$(printf "%s" "$stripped_output" | grep -c "\[FAIL\]")
total_checks=$((pass_count + fail_count))

if [ "$total_checks" -eq 0 ]; then
    score=0
else
    score=$(( 100 * pass_count / total_checks ))
fi

echo
printf "\e[1mAudit Summary:\e[0m\n"
printf "  Passed : %s\n" "$pass_count"
printf "  Failed : %s\n" "$fail_count"
printf "  Total  : %s\n" "$total_checks"
printf "\e[1mCompliance Score: \e[32m%s%%\e[0m\n" "$score"
