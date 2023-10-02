FROM cybersecnatlab/socaz:python-3.11-alpine
WORKDIR /usr/src/app
RUN mkdir /challenge
WORKDIR /challenge
COPY server.py requirements.txt flag.jpg ./
RUN pip install --no-cache-dir -r ./requirements.txt && \
    chmod +x ./server.py
EXPOSE 5555
CMD ["socaz", "--bind", "5555", "--cmd", "env PYTHONUNBUFFERED=1 ./server.py"]
