ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LC_DATA=/data LC_HOST=0.0.0.0
WORKDIR /app
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --upgrade pip==26.2.2 && python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && groupadd --gid 10001 license && useradd --uid 10001 --gid 10001 --no-create-home license \
    && mkdir /data && chown license:license /data
COPY --chown=license:license center ./center
COPY --chown=license:license sdk ./sdk
COPY --chown=license:license release.json ./release.json
COPY --chown=license:license deploy/entrypoint.sh /entrypoint.sh
RUN chmod -R a+rX /app/center /app/sdk && chmod 644 /app/release.json && chmod 755 /entrypoint.sh
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready',timeout=3)"
ENTRYPOINT ["/entrypoint.sh"]
CMD ["serve"]
