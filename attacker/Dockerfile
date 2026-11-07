FROM python:3.12-slim
WORKDIR /app
# Vendored wheels: builds with no internet, and the lab stays reproducible/offline.
COPY wheels/ /wheels/
RUN pip install --no-index --find-links=/wheels h2==4.4.1
COPY attack.py .
ENTRYPOINT ["python", "-u", "attack.py"]
CMD ["idle", "--duration", "3600"]
