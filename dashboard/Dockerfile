FROM python:3.12-slim
# docker.io gives us the plain `docker` CLI so the dashboard can launch
# attacker containers on button click (talks to the host engine over the
# mounted docker.sock). We only ever call `docker run`, no compose plugin
# needed.
RUN apt-get update && apt-get install -y --no-install-recommends docker-cli \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py index.html ./
EXPOSE 8088
CMD ["python", "-u", "app.py"]
