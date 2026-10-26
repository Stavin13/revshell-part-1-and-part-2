FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        netcat-openbsd \
        procps \
        tcpdump \
        yara \
    && rm -rf /var/lib/apt/lists/*

RUN printf 'set enable-bracketed-paste off\n' >> /etc/inputrc

WORKDIR /opt/revshell
COPY shell.py reconnect_shell.py encrypted_shell.py encrypted_listener.py frame_probe.py reverse_shell.yar README.md ./

CMD ["/bin/bash"]
