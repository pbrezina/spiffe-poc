FROM quay.io/freeipa/freeipa-server:fedora-rawhide

# IPA container relies on /data volume that we must create for the build
# process.

RUN cp -a /data-template/. /data/ && \
    mkdir -p /tmp/var/tmp && \
    dnf copr enable -y pbrezina/s4u && \
    dnf install -y openssh-server sssd-kcm oddjob oddjob-mkhomedir && \
    dnf upgrade -y freeipa-server sssd\* && \
    dnf clean all && \
    authselect enable-feature with-gssapi && \
    authselect enable-feature with-mkhomedir && \
    systemctl enable sshd sssd-kcm.socket oddjobd && \
    cp -a /data/. /data-template/

# Copy sssd.conf with correct ownership and permissions
COPY --chown=root:sssd --chmod=640 sssd.conf /data-template/etc/sssd/sssd.conf

# Copy login.defs to override UID_MAX and GID_MAX
COPY --chown=root:root --chmod=644 login.defs /etc/login.defs
