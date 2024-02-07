#
# docker run -d --restart unless-stopped --name jumphost \
# -p 8118:8118 \
# --mount type=bind,source="$HOME"/.ssh/id_rsa,target=/root/.ssh/id_rsa,readonly \
# --mount type=bind,source="$(pwd)"/credentials.yaml,target=/opt/credentials.yaml,readonly \
# --mount type=bind,source="$(pwd)"/jumphost.yaml,target=/opt/jumphost.yaml,readonly \
# --mount type=bind,source="$(pwd)"/local.yaml,target=/opt/local.yaml,readonly \
# --hostname jumphost jumphost
#
FROM python:3.11-alpine3.18
#RUN pip3 install cryptography PyYAML asyncssh aiosocks uvloop lockfile python-daemon pykeepass
COPY pyproject.toml /opt/
COPY jumphost /opt/jumphost/
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir --upgrade /opt
WORKDIR /opt
EXPOSE 8118
#CMD ["./jumphost.py", "--forti", "-vvf"]
CMD ["jumphost", "-vvf"]
