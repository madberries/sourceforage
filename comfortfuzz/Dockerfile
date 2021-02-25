FROM ubuntu:16.04
ENV COMFORT_FUZZ_HOME=/home/haccs/comfortfuzz
ENV COMFORT_RUNNER=dfsan

# Install basic dependencies
RUN apt-get update && \
       apt-get -y install sudo git wget vim silversearcher-ag

# Create haccs user, and copy over gitlab private key for repo access
RUN useradd -m haccs && echo "haccs:haccs" | chpasswd && adduser haccs sudo
COPY gitlab_key /home/haccs/
COPY run_comfuzz /home/haccs/
COPY run_exploit /home/haccs/
RUN chmod a+x /home/haccs/run_comfuzz
RUN chmod a+x /home/haccs/run_exploit
RUN chown haccs:haccs /home/haccs/gitlab_key

# Workaround for systemd (neo4j dependency installs and starts a systemd
# service)
RUN wget https://raw.githubusercontent.com/gdraheim/docker-systemctl-replacement/master/files/docker/systemctl.py \
       -O /usr/local/bin/systemctl
RUN chmod a+x /usr/local/bin/systemctl

# Allow haccs passwordless sudo access
RUN echo 'haccs   ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

USER haccs
WORKDIR /home/haccs

# Setup SSH key for repo access, and clone the comfortfuzz
RUN mkdir .ssh && touch .ssh/known_hosts && \
    eval $(ssh-agent) && ssh-add gitlab_key && \
    ssh-keyscan -H gitlab.com >> /home/haccs/.ssh/known_hosts && \
    git clone git@gitlab.com:aarnolabs/llvm/comfortfuzz.git

# Install comfortfuzz
WORKDIR /home/haccs/comfortfuzz
RUN git checkout 7518b2f5
RUN eval $(ssh-agent) && ssh-add /home/haccs/gitlab_key && \
    ./install_comfortfuzz.sh

# Finally, we should be operating under haccs home directory
WORKDIR /home/haccs
