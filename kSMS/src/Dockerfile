FROM ubuntu:22.04

# Update and install packages
RUN apt-get update
RUN apt-get install -y --no-install-recommends \
    qemu-system-x86 \
    socat \
    python3

# Copy challenge entrypoint
COPY entrypoint.sh /opt/
RUN chmod +x /opt/entrypoint.sh

COPY flag.txt /opt/

WORKDIR /opt/

# Socat listening port
EXPOSE 1337

# Change entrypoint to launch challenge
CMD ["./entrypoint.sh"]
