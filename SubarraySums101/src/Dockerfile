FROM cybersecnatlab/socaz:python-3.11-alpine

USER root

WORKDIR /app

COPY ./server.py .

ENTRYPOINT ["socaz", "-t", "120", "--bind", "5555", "--cmd", "python server.py"]