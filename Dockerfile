# The proxy is a plain ASGI app; the only thing it needs from the host is the
# Docker socket. It does not need the docker CLI -- it speaks the Engine API.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

COPY otproxy /app/otproxy

# Runs as a normal user. Access to the Docker socket comes from the group the
# socket belongs to on the host -- see group_add in the compose file. Do not
# paper over a permission error by switching this back to root: the socket is
# the whole host, and this process is the thing exposed to Open WebUI.
RUN useradd --create-home --uid 10001 otproxy
USER otproxy

EXPOSE 8800

# No curl in the image; the check uses what is already here.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('OTPROXY_PORT','8800')+'/health', timeout=4).status==200 else 1)"]

ENTRYPOINT ["python", "-m", "otproxy"]
