FROM fedora:latest

# Install dependencies
RUN dnf install -y python3 python3-pip gcc python3-devel \
        krb5-workstation krb5-devel openssl openssh-clients && \
    dnf clean all

# Create virtual environment
RUN python3 -m venv /opt/venv

# Install Python dependencies
RUN /opt/venv/bin/pip3 install --no-cache-dir spiffe gssapi krb5 paramiko

# Copy Kerberos configuration
COPY krb5.conf /etc/krb5.conf

# Set the working directory
WORKDIR /mcp

# Use the virtual environment by default
ENV PATH="/opt/venv/bin:$PATH"

# Set the entrypoint
ENTRYPOINT ["/mcp/mcp.py"]
