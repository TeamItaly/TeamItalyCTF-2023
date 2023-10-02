FROM ubuntu:22.04

RUN apt-get update && apt-get install socat -y

RUN adduser --disabled-password ctf 
ADD ./log /home/ctf/log
ADD ./flag /home/ctf/flag


WORKDIR /home/ctf
USER ctf

CMD ["socat", "-t", "60", "-T", "60", "TCP4-LISTEN:9001,reuseaddr,fork", "EXEC:'/home/ctf/log'"]
