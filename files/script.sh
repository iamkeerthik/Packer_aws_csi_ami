
#!/bin/bash

#Hardening Script for AmazonLinux
#sudo -i
#vi harden.sh
#chmod +x harden.sh
#./harden.sh

echo "---------- Linux System Hardening Process Started ----------"

#1.1.2 Ensure /tmp is configured
echo "tmpfs /tmp tmpfs defaults,rw,nodev,nosuid,noexec,relatime 0 0" >> /etc/fstab

#1.1.17 Ensure noexec option set on /dev/shm partition 
echo "tmpfs /dev/shm tmpfs defaults,rw,nodev,nosuid,noexec,relatime 0 0" >> /etc/fstab
sleep 2

#1.1.1.1 Ensure mounting of cramfs filesystems is disabled
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.2 Ensure mounting of hfs filesystems is disabled 
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.3 Ensure mounting of hfsplus filesystems is disabled
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.4 Ensure mounting of squashfs filesystems is disabled
echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.5 Ensure mounting of udf filesystems is disabled 
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf

echo "---> Mounting of Filesystems has been Disabled"

#1.3.1 Ensure AIDE is installed 
yum -y install aide
echo "---> Intializing AIDE (Advanced Intrusion Detection Environment)"
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

#1.3.2 Ensure filesystem integrity is regularly checked 
echo "0 5 * * * /usr/sbin/aide --check" >> /etc/crontab

#1.4.1 Ensure permissions on bootloader config are configured 
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

#1.5.1 Ensure core dumps are restricted 
echo "* hard core 0" >> /etc/security/limits.conf
sleep 5

#1.7.1.1 Ensure message of the day is configured properly
\cp /dev/null /etc/motd
echo "-------------------------------------------------------------------------" > /etc/motd
echo "------------------------ 42GEARS MOBILITY SYSTEMS -----------------------" >> /etc/motd
echo "-------------------------------------------------------------------------" >> /etc/motd
sudo update-motd --disable

#1.7.1.2 Ensure local login warning banner is configured properly 
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue

#1.7.1.3 Ensure remote login warning banner is configured properly 
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net

#3.3.3 Ensure /etc/hosts.deny is configured 
echo "sshd: ALL: allow" >> /etc/hosts.deny
echo "ALL: ALL" >> /etc/hosts.deny
echo "sshd: ALL" >> /etc/hosts.allow

#3.4.1 Ensure DCCP is disabled 
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf

#3.4.2 Ensure SCTP is disabled 
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf

#3.4.3 Ensure RDS is disabled 
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf

#3.4.4 Ensure TIPC is disabled 
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
sleep 2

echo "---> Installing iptables services"
yum -y install iptables-services
sleep 10

#3.5.1.1 Ensure default deny firewall policy
#3.5.1.2 Ensure loopback traffic is configured 
echo "---> Setting up iptables"
\cp /dev/null /etc/sysconfig/iptables
cat <<EOT >> /etc/sysconfig/iptables
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -s 127.0.0.0/8 -j DROP
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
COMMIT
EOT
systemctl enable iptables
sudo chkconfig iptables on
sudo service iptables start
sleep 5

#3.5.2.1 Ensure IPv6 default deny firewall policy 
#3.5.2.2 Ensure IPv6 loopback traffic is configured
echo "---> Setting up ip6tables"
\cp /dev/null /etc/sysconfig/ip6tables
cat <<EOT >> /etc/sysconfig/ip6tables
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -s ::1 -j DROP
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
COMMIT
EOT
systemctl enable ip6tables
sudo chkconfig ip6tables on
sudo service ip6tables start
sleep 10

#4.2.1.3 Ensure rsyslog default file permissions configured 
echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
echo "\$FileCreateMode 0640" >> /etc/rsyslog.d/21-cloudinit.conf
echo "\$FileCreateMode 0640" >> /etc/rsyslog.d/listen.conf

#5.6 Ensure access to the su command is restricted 
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su

#5.1.2 Ensure permissions on /etc/crontab are configured 
#5.1.3 Ensure permissions on /etc/cron.hourly are configured 
#5.1.4 Ensure permissions on /etc/cron.daily are configured 
#5.1.5 Ensure permissions on /etc/cron.weekly are configured 
#5.1.6 Ensure permissions on /etc/cron.monthly are configured
#5.1.7 Ensure permissions on /etc/cron.d are configured 
chown root:root /etc/cron*
chmod og-rwx /etc/cron*
sleep 5

#5.1.8 Ensure at/cron is restricted to authorized users 
\rm /etc/cron.deny
\rm /etc/at.deny
sleep 2
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow 
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow 
chown root:root /etc/at.allow

#5.3.1 Ensure password creation requirements are configured 
echo "minlen=14" >> /etc/security/pwquality.conf
echo "dcredit=-1" >> /etc/security/pwquality.conf
echo "ucredit=-1" >> /etc/security/pwquality.conf 
echo "ocredit=-1" >> /etc/security/pwquality.conf
echo "lcredit=-1" >> /etc/security/pwquality.conf

#5.3.2 Ensure lockout for failed password attempts is configured 
echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900" >> /etc/pam.d/password-auth
echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900" >> /etc/pam.d/password-auth
echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900" >> /etc/pam.d/password-auth
echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth

#5.3.3 Ensure password reuse is limited 
echo "password sufficient pam_unix.so remember=5 try_first_pass use_authtok nullok sha512 shadow" >> /etc/pam.d/password-auth
echo "password sufficient pam_unix.so remember=5 try_first_pass use_authtok nullok sha512 shadow" >> /etc/pam.d/system-auth

#5.4.4 Ensure default user umask is 027 or more restrictive
sed -i.bak 's/umask 002/umask 027/g' /etc/profile
sed -i.bak 's/umask 022/umask 027/g' /etc/profile
sed -i.bak 's/umask 002/umask 027/g' /etc/bashrc
sed -i.bak 's/umask 022/umask 027/g' /etc/bashrc

#5.4.1.4 Ensure inactive password lock is 30 days or less 
useradd -D -f 30 
chage --inactive 30 ec2-user

#5.4.1.1 Ensure password expiration is 365 days or less 
echo "PASS_MAX_DAYS 90" >> /etc/login.defs

#5.4.1.2 Ensure minimum days between password changes is 7 or more 
chage --mindays 7 ec2-user
echo "PASS_MIN_DAYS 7" >> /etc/login.defs
echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
sleep 5

echo "---> Applying sshd_config changes"
#5.2.4 Ensure SSH Protocol is set to 2 
#5.2.5 Ensure SSH LogLevel is appropriate
#5.2.7 Ensure SSH MaxAuthTries is set to 4 or less 
#5.2.8 Ensure SSH IgnoreRhosts is enabled 
#5.2.9 Ensure SSH HostbasedAuthentication is disabled 
#5.2.10 Ensure SSH root login is disabled 
#5.2.11 Ensure SSH PermitEmptyPasswords is disabled 
#5.2.12 Ensure SSH PermitUserEnvironment is disabled 
#5.2.13 Ensure only strong ciphers are used 
#5.2.14 Ensure only strong MAC algorithms are used 
#5.2.15 Ensure that strong Key Exchange algorithms are used 
#5.2.16 Ensure SSH Idle Timeout Interval is configured 
#5.2.17 Ensure SSH LoginGraceTime is set to one minute or less 
#5.2.18 Ensure SSH access is limited 
#5.2.19 Ensure SSH warning banner is configured 
sed -i.bak 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
cat <<EOT >> /etc/ssh/sshd_config
Protocol 2
LogLevel INFO
X11Forwarding no
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
AllowUsers ec2-user
Banner /etc/issue.net
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
EOT
sleep 5 

echo "---> Applying sysctl changes"
#1.5.2 Ensure address space layout randomization (ASLR) is enabled
#3.1.1 Ensure IP forwarding is disabled 
#3.1.2 Ensure packet redirect sending is disabled 
#3.2.1 Ensure source routed packets are not accepted 
#3.2.2 Ensure ICMP redirects are not accepted 
#3.2.3 Ensure secure ICMP redirects are not accepted 
#3.2.4 Ensure suspicious packets are logged 
#3.2.5 Ensure broadcast ICMP requests are ignored 
#3.2.6 Ensure bogus ICMP responses are ignored 
#3.2.7 Ensure Reverse Path Filtering is enabled 
cat <<EOT >> /etc/sysctl.conf
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOT
sleep 10

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
sleep 2

sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
sleep 1

sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
sleep 2

sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
sleep 1

sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
sleep 1

sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
sleep 2

echo "------- Linux System Hardening (CIS Benchmark - Level 1) has been Completed! -------"
AmazonLinux-HardeningScript.sh
Displaying AmazonLinux-HardeningScript.sh.