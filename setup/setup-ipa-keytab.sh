#!/usr/bin/env bash

echo "Initializing IPA"

# Remove nologin file to we can SSH into the machine
podman exec ipa rm -f /run/nologin

# Enroll staging container to IPA
echo "Secret123" | podman exec -i staging realm join -U admin ipa.example.org


# Restore sssd configuration that was overriden by ipa-server-install
podman exec ipa cp /data-template/etc/sssd/sssd.conf /etc/sssd/sssd.conf
podman exec ipa systemctl restart sssd

# kinit so we can run administrative ipa commands
podman exec ipa systemctl start sssd-kcm.socket
echo "Secret123" | podman exec -i ipa kinit admin

# Create service principal that can acquire S4U tickets
podman exec ipa ipa host-add mcp.example.org --force
podman exec ipa ipa service-add mcp/mcp.example.org --ok-to-auth-as-delegate=true --force
podman exec ipa ipa service-add-attestation-key mcp/mcp.example.org --type="mcp" --pubkey=/certs/mcp.crt
podman exec ipa ipa-getkeytab -s ipa.example.org -p mcp/mcp.example.org -k /certs/tmp/mcp.keytab

# Setup S4U2Proxy delegation mcp -> ipa server
podman exec ipa ipa servicedelegationtarget-add mcp-delegation
podman exec ipa ipa servicedelegationtarget-add-member mcp-delegation --principals=host/ipa.example.org
podman exec ipa ipa servicedelegationrule-add mcp-s4u2proxy-rule
podman exec ipa ipa servicedelegationrule-add-member mcp-s4u2proxy-rule --principals=mcp/mcp.example.org
podman exec ipa ipa servicedelegationrule-add-target mcp-s4u2proxy-rule --servicedelegationtargets=mcp-delegation

# Setup ssh to acquire S4U2Self (for sudo, nfs mounts, ...) and S4U2Proxy to HTTP/ipa.example.org (to run ipa)
podman exec ipa bash -c 'ipa host-mod ipa.example.org --sshpubkey="$(cat /etc/ssh/ssh_host_rsa_key.pub)"'
podman exec ipa ipa service-add-delegation HTTP/ipa.example.org host/ipa.example.org

# Add sudo rule to allow admin user run sudo
podman exec ipa ipa sudorule-add admin-all \
    --desc="Allow admin to run any command on any host" \
    --hostcat=all --cmdcat=all
podman exec ipa ipa sudorule-add-user admin-all --users=admin
