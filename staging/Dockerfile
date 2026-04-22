FROM fedora:latest

RUN dnf copr enable -y pbrezina/s4u
RUN dnf install -y openssh-server freeipa-client sssd\* oddjob oddjob-mkhomedir && \
    dnf clean all

RUN authselect select sssd with-gssapi with-mkhomedir --force
RUN systemctl enable sshd sssd-kcm.socket oddjobd

COPY --chown=root:root --chmod=644 login.defs /etc/login.defs
