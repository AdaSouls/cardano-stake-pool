# SOULS node hardening runbook

Debian 12, `cardano-node` running as user `cardano`, one block producer
(BP) and two relays on VPS. Written from the Lynis audit of relay 1
(2026-11-04: index 65, 0 warnings, 50 suggestions) and from what a Cardano
node needs that Lynis does not measure.

Run the steps in order, one node at a time, **relay 2 first** (least
damage if something goes wrong), then relay 1, then the BP. Every step
says which nodes it applies to, what it changes, and how to verify it.
Commands are idempotent: running a step twice is safe.

> Keep a second SSH session open to the node for the whole runbook. Do not
> close it until step 3 (SSH) and step 4 (firewall) are verified from a
> fresh connection.

## 0. Variables

Set these once per shell before starting. Everything below uses them.

```bash
export NODE_ROLE=relay            # relay | bp
export ADMIN_USER=cardano         # the only user allowed over SSH
export SSH_PORT=22                # change if you move SSH; update the firewall step too
export NODE_PORT=6000             # cardano-node listening port on this host
export ADMIN_IPS="203.0.113.10"   # your home/office IPs, space-separated (SSH from anywhere else is dropped)
export RELAY_IPS="198.51.100.11 198.51.100.12"   # public IPs of relay 1 and relay 2
export BP_IP="198.51.100.20"      # public IP of the block producer (relays need it; the BP does not)
export CNODE_HOME=/opt/cardano/cnode   # where cardano-node's config, db and keys live
```

Find the current values on the node before trusting the defaults:

```bash
ss -ltnp | grep -E 'sshd|cardano-node'      # ports actually listening
systemctl list-units --type=service | grep -i -E 'cardano|cnode'   # the node's unit name
id cardano; ls -la "$CNODE_HOME" 2>/dev/null
grep -E '^(Port|PasswordAuthentication|PermitRootLogin|AllowUsers)' /etc/ssh/sshd_config
```

## 1. Inventory: what must not be on a relay — all nodes

A relay holds no keys. If any of these exist on a relay, move them off
the machine (to the offline machine or the BP) before anything else.

```bash
sudo find / -xdev -type f \( -name '*.skey' -o -name 'kes.skey' -o -name 'vrf.skey' -o -name 'node.cert' -o -name 'cold*.skey' -o -name 'payment.skey' -o -name 'stake.skey' -o -name 'drep.skey' \) 2>/dev/null
```

Expected on a **relay**: nothing. Expected on the **BP**: only `kes.skey`,
`vrf.skey`, `node.cert` (the operational certificate). `cold.skey`,
`payment.skey`, `stake.skey` and `drep.skey` belong on the offline
machine, never on any online node. Fix permissions on the BP:

```bash
# BP only
sudo chown cardano:cardano "$CNODE_HOME"/priv/pool/*/{kes.skey,vrf.skey,node.cert} 2>/dev/null
sudo chmod 400 "$CNODE_HOME"/priv/pool/*/{kes.skey,vrf.skey} 2>/dev/null
sudo chmod 444 "$CNODE_HOME"/priv/pool/*/node.cert 2>/dev/null
sudo find "$CNODE_HOME" -name '*.skey' -exec ls -l {} \;       # every line must read -r-------- cardano cardano
```

## 2. Packages: update, clean, add the tools — all nodes

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y fail2ban needrestart auditd audispd-plugins aide aide-common apt-listbugs apt-show-versions debsums libpam-tmpdir unattended-upgrades
# 33 old kernels and 32 removed-but-unpurged packages in the audit:
sudo apt autoremove --purge -y
dpkg -l | awk '/^rc/{print $2}' | xargs -r sudo dpkg --purge
# verify
dpkg -l 'linux-image-*' | grep '^ii' | wc -l            # 2 is enough (current + previous)
dpkg -l | awk '/^rc/' | wc -l                           # 0
sudo needrestart -r l                                   # lists services holding old libraries; restart them or reboot in a window
```

Compilers: a production node should not have a toolchain. If
`cardano-node` was built on this machine, build on a separate box from now
on and copy the binary.

```bash
dpkg -l gcc g++ make cpp ghc cabal-install 2>/dev/null | grep '^ii'
sudo apt purge -y gcc g++ make cpp 2>/dev/null && sudo apt autoremove --purge -y
# if you must keep them, root-only:
for b in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/make; do [ -e "$b" ] && sudo chmod 700 "$b"; done
```

Unattended upgrades are installed; make sure they are on and reboot only when you say so:

```bash
sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
sudo sed -i 's|^//\?\s*Unattended-Upgrade::Automatic-Reboot .*|Unattended-Upgrade::Automatic-Reboot "false";|' /etc/apt/apt.conf.d/50unattended-upgrades
sudo unattended-upgrade --dry-run --debug 2>&1 | tail -3
```

## 3. SSH — all nodes

Order matters: add the key-only user restrictions, test the config, reload,
then confirm from a **new** session before closing the old one.

```bash
sudo install -d -m 755 /etc/ssh/sshd_config.d
sudo tee /etc/ssh/sshd_config.d/10-souls-hardening.conf >/dev/null <<EOF
Port ${SSH_PORT}
Protocol 2
AllowUsers ${ADMIN_USER}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
X11Forwarding no
Compression no
TCPKeepAlive no
UseDNS no
LogLevel VERBOSE
PermitUserEnvironment no
StrictModes yes
Banner /etc/issue.net
# Modern algorithms only
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
EOF
# make sure your key is really there before locking passwords out
sudo test -s /home/${ADMIN_USER}/.ssh/authorized_keys && echo "authorized_keys present" || echo "STOP: no authorized_keys for ${ADMIN_USER}"
sudo chmod 700 /home/${ADMIN_USER}/.ssh && sudo chmod 600 /home/${ADMIN_USER}/.ssh/authorized_keys
sudo chmod 600 /etc/ssh/sshd_config
# legal banner (BANN-7126/7130)
sudo tee /etc/issue /etc/issue.net >/dev/null <<'EOF'
Authorized access only. All connections are logged.
EOF
sudo sshd -t && sudo systemctl reload ssh
sudo sshd -T | grep -E '^(allowusers|passwordauthentication|permitrootlogin|maxauthtries|allowtcpforwarding|x11forwarding|loglevel)'
```

Now, from your machine, open a **new** terminal: `ssh -p $SSH_PORT $ADMIN_USER@<node>`.
Only when it works, close the old session.

## 4. Firewall (nftables) — per role

Debian 12 ships nftables; the audit shows legacy iptables rules with
unused entries. Replace them with one ruleset per role. The `at` job
below restores open access in 10 minutes unless you cancel it, so a typo
cannot lock you out.

```bash
sudo apt install -y nftables at && sudo systemctl enable --now nftables atd
sudo cp /etc/nftables.conf /etc/nftables.conf.bak.$(date +%s)
# safety net: flush rules in 10 minutes unless cancelled
echo "nft flush ruleset" | sudo at now + 10 minutes
```

**Relays** (`NODE_ROLE=relay`): SSH from admin IPs, node port from anywhere, outbound free.

```bash
ADMIN_SET=$(echo $ADMIN_IPS | sed 's/ /, /g')
sudo tee /etc/nftables.conf >/dev/null <<EOF
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  set admin_ips { type ipv4_addr; elements = { ${ADMIN_SET} } }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } limit rate 10/second accept
    ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
    tcp dport ${SSH_PORT} ip saddr @admin_ips ct state new limit rate 6/minute accept
    tcp dport ${NODE_PORT} ct state new accept
    counter drop
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
```

**Block producer** (`NODE_ROLE=bp`): SSH from admin IPs, node port **only from the relays**, nothing else.

```bash
ADMIN_SET=$(echo $ADMIN_IPS | sed 's/ /, /g'); RELAY_SET=$(echo $RELAY_IPS | sed 's/ /, /g')
sudo tee /etc/nftables.conf >/dev/null <<EOF
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  set admin_ips { type ipv4_addr; elements = { ${ADMIN_SET} } }
  set relay_ips { type ipv4_addr; elements = { ${RELAY_SET} } }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
    tcp dport ${SSH_PORT} ip saddr @admin_ips ct state new limit rate 6/minute accept
    tcp dport ${NODE_PORT} ip saddr @relay_ips ct state new accept
    counter drop
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
    # the node talks only to the relays; the OS needs DNS, NTP, apt (https)
    ip daddr @relay_ips tcp dport ${NODE_PORT} accept
    udp dport { 53, 123 } accept
    tcp dport { 53, 80, 443 } accept
    counter drop
  }
}
EOF
```

Apply and verify (both roles):

```bash
sudo nft -c -f /etc/nftables.conf && sudo nft -f /etc/nftables.conf
sudo nft list ruleset
# from a NEW terminal: ssh in, and from a relay: nc -zv <bp-ip> $NODE_PORT
# if everything works, cancel the safety net:
sudo atq && sudo atrm $(sudo atq | awk '{print $1}')
# retire legacy iptables so the two stacks don't fight
sudo iptables -F; sudo iptables -X; sudo ip6tables -F; sudo ip6tables -X 2>/dev/null
sudo systemctl disable --now netfilter-persistent 2>/dev/null; sudo apt purge -y iptables-persistent 2>/dev/null
sudo systemctl is-enabled nftables     # enabled
```

The BP's topology must list only its relays, and the relays' topology must
include the BP as a local root. Check:

```bash
grep -n -E '"(address|addr)"|localRoots|publicRoots|useLedgerAfterSlot' "$CNODE_HOME"/files/topology.json | head -30
```

## 5. fail2ban — all nodes

```bash
sudo tee /etc/fail2ban/jail.local >/dev/null <<EOF
[DEFAULT]
backend = systemd
banaction = nftables-multiport
bantime  = 1h
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1 ${ADMIN_IPS// / }

[sshd]
enabled = true
port    = ${SSH_PORT}
mode    = aggressive
EOF
sudo systemctl enable --now fail2ban && sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

## 6. Kernel and network sysctl — all nodes

The values Lynis flagged, plus the ones a public node wants. Nothing here
affects `cardano-node`'s throughput.

```bash
sudo tee /etc/sysctl.d/90-souls-hardening.conf >/dev/null <<'EOF'
# routing / spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
# kernel
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
kernel.core_uses_pid = 1
kernel.randomize_va_space = 2
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
# a node benefits from larger buffers; harmless on a VPS
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF
sudo sysctl --system >/dev/null && sudo sysctl net.ipv4.conf.all.rp_filter kernel.kptr_restrict kernel.sysrq kernel.unprivileged_bpf_disabled
```

Do **not** set `kernel.modules_disabled=1` on a VPS: it is irreversible until reboot and breaks some hypervisor guest agents. Leave it.

Unused protocols and drivers (NETW-3200, USB-1000, STRG-1846):

```bash
sudo tee /etc/modprobe.d/souls-blacklist.conf >/dev/null <<'EOF'
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install usb-storage /bin/false
install firewire-core /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
EOF
sudo update-initramfs -u
```

Core dumps off (KRNL-5820):

```bash
echo '* hard core 0' | sudo tee /etc/security/limits.d/90-nocore.conf >/dev/null
sudo mkdir -p /etc/systemd/coredump.conf.d && printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' | sudo tee /etc/systemd/coredump.conf.d/disable.conf >/dev/null
```

## 7. Accounts, PAM, umask, permissions — all nodes

```bash
# password policy for the few local accounts that still have one
sudo sed -i -E 's/^#?\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/; s/^#?\s*PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/; s/^#?\s*UMASK.*/UMASK 027/; s/^#?\s*SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 65536/; s/^#?\s*SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 65536/' /etc/login.defs
grep -q SHA_CRYPT_MIN_ROUNDS /etc/login.defs || echo 'SHA_CRYPT_MIN_ROUNDS 65536' | sudo tee -a /etc/login.defs
sudo apt install -y libpam-pwquality
sudo sed -i 's/^password\s\+requisite\s\+pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=14 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
# session timeout for idle shells
echo 'readonly TMOUT=900; export TMOUT' | sudo tee /etc/profile.d/99-tmout.sh >/dev/null
echo 'umask 027' | sudo tee /etc/profile.d/99-umask.sh >/dev/null
# permissions Lynis flagged
sudo chmod 750 /etc/sudoers.d
sudo chmod 750 /home/${ADMIN_USER}
sudo chmod 600 /etc/crontab && sudo chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
# accounts with a shell: only root and the admin should remain
awk -F: '$7 !~ /(nologin|false)$/ {print $1": "$7}' /etc/passwd
```

## 8. auditd and file integrity — all nodes

auditd records who touched what; AIDE tells you if a binary or config changed.

```bash
sudo tee /etc/audit/rules.d/90-souls.rules >/dev/null <<EOF
-D
-b 8192
-f 1
# identity, sudo, ssh, cron, time
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /etc/nftables.conf -p wa -k firewall
-w /etc/systemd/system/ -p wa -k systemd
# the node itself: binaries, config and, on the BP, the keys
-w /usr/local/bin/cardano-node -p wa -k cardano
-w /usr/local/bin/cardano-cli -p wa -k cardano
-w ${CNODE_HOME}/files/ -p wa -k cardano-config
-w ${CNODE_HOME}/priv/ -p rwa -k cardano-keys
-a always,exit -F arch=b64 -S execve -F euid=0 -k rootcmd
-e 2
EOF
sudo augenrules --load && sudo systemctl enable --now auditd
sudo auditctl -l | wc -l
# AIDE baseline (takes a few minutes; the db is the thing you compare against later)
sudo sed -i 's|^#\?\s*Checksums.*|Checksums = sha512|' /etc/aide/aide.conf 2>/dev/null || true
printf '%s\n' "${CNODE_HOME}/files R" "${CNODE_HOME}/priv R" "/usr/local/bin R" | sudo tee /etc/aide/aide.conf.d/99_souls >/dev/null
sudo aideinit -y -f
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# daily check mails root; keep a copy of aide.db off the machine too
sudo cp /var/lib/aide/aide.db /root/aide.db.$(hostname).$(date +%F)
echo "copy /root/aide.db.$(hostname).$(date +%F) to the offline machine"
```

Process accounting (ACCT-9622/9626), cheap and useful after an incident:

```bash
sudo apt install -y acct sysstat && sudo systemctl enable --now acct sysstat
sudo sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat
```

## 9. cardano-node under systemd hardening — all nodes

Lynis reports most services as UNSAFE. The one that matters is the node.
Add a drop-in; it changes nothing about how the node runs, only what it
may touch. Adjust `ReadWritePaths` to where the db and sockets live.

```bash
UNIT=$(systemctl list-units --type=service --all | awk '/cardano|cnode/ {print $1; exit}'); echo "unit: $UNIT"
sudo mkdir -p /etc/systemd/system/${UNIT}.d
sudo tee /etc/systemd/system/${UNIT}.d/90-hardening.conf >/dev/null <<EOF
[Service]
User=cardano
Group=cardano
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${CNODE_HOME}/db ${CNODE_HOME}/sockets ${CNODE_HOME}/logs
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=no
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
LimitNOFILE=1048576
Restart=always
RestartSec=5
EOF
sudo systemctl daemon-reload && sudo systemctl restart ${UNIT}
sleep 20; sudo systemctl status ${UNIT} --no-pager | head -8
sudo systemd-analyze security ${UNIT} | tail -1       # aim for < 4.0 (was ~9.x)
journalctl -u ${UNIT} -n 20 --no-pager | grep -i -E 'error|denied|permission' || echo "no permission errors"
```

If the node fails to start, the usual cause is a path missing from
`ReadWritePaths` (db, sockets, logs, or a `priv` directory the BP reads).
Add it and restart; do not remove `ProtectSystem=strict`.

## 10. Time, logs, boot — all nodes

```bash
# chrony is in place and healthy per the audit; confirm sources
chronyc tracking | head -4
# journald: persistent, bounded, and remote copy later when there are >2 machines
sudo mkdir -p /var/log/journal && sudo sed -i 's/^#\?Storage=.*/Storage=persistent/; s/^#\?SystemMaxUse=.*/SystemMaxUse=2G/' /etc/systemd/journald.conf && sudo systemctl restart systemd-journald
# GRUB password is low value on a VPS without console access; skip unless the provider exposes a VNC console. If it does:
# grub-mkpasswd-pbkdf2  -> put 'set superusers="root"' and 'password_pbkdf2 root <hash>' in /etc/grub.d/40_custom, then update-grub
```

## 11. Verify — all nodes

```bash
sudo lynis audit system --quick 2>/dev/null | grep -E 'Hardening index|Warnings|Suggestions'
sudo sshd -T | grep -E '^(allowusers|passwordauthentication|maxauthtries)'
sudo nft list ruleset | grep -c dport
sudo fail2ban-client status sshd | grep -E 'Currently banned|Total failed'
sudo systemd-analyze security ${UNIT} | tail -1
sudo aide --check --config /etc/aide/aide.conf 2>/dev/null | tail -3
sudo find / -xdev -name '*.skey' 2>/dev/null        # relays: empty; BP: kes.skey, vrf.skey only
```

Target after this runbook: Lynis index ≥ 80, SSH key-only from your IPs,
node port open only where the role needs it, auditd + AIDE baselines
stored off-box, `cardano-node` at systemd exposure < 4.

## Per-node checklist

| Step | relay 2 | relay 1 | BP |
| --- | --- | --- | --- |
| 1 Inventory (no keys on relays; 400 on BP keys) | ☐ | ☐ | ☐ |
| 2 Packages, purge, no compilers | ☐ | ☐ | ☐ |
| 3 SSH (verified from a new session) | ☐ | ☐ | ☐ |
| 4 Firewall (role ruleset, safety net cancelled, iptables retired) | ☐ | ☐ | ☐ |
| 5 fail2ban | ☐ | ☐ | ☐ |
| 6 sysctl, module blacklist, no core dumps | ☐ | ☐ | ☐ |
| 7 Accounts, PAM, umask, permissions | ☐ | ☐ | ☐ |
| 8 auditd + AIDE baseline copied off-box | ☐ | ☐ | ☐ |
| 9 cardano-node systemd drop-in, exposure < 4 | ☐ | ☐ | ☐ |
| 10 journald persistent | ☐ | ☐ | ☐ |
| 11 Verify, record the new Lynis index here | ☐ | ☐ | ☐ |

## What this runbook does not cover

- KES rotation and the operational certificate (`docs/runbooks` in
  `cardano-governance` has the pool-update flow; KES is its own runbook).
- Backups of the BP's `priv/` to the offline machine.
- A bastion host. With two admin IPs and key-only SSH it is not needed yet;
  it becomes worth it when more than one person administers the nodes.
- Monitoring. The on-chain side (blocks, KES periods, pledge, saturation)
  is what the SPO Sentinel agent in `reference-agents` will publish;
  host metrics stay private (node_exporter + Prometheus, when you want them).
