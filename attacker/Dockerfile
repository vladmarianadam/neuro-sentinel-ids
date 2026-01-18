FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y \
    hping3 \
    hydra \
    nmap \
    curl \
    iputils-ping \
    && apt-get clean
ENTRYPOINT ["tail", "-f", "/dev/null"]