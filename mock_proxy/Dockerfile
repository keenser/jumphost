FROM alpine:3.14
RUN apk add --update python3 py3-pip py3-aiohttp py3-yaml openssl
RUN pip3 install aiohttp_sse
RUN openssl req \
 -x509 \
 -newkey rsa:2048 \
 -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
 -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
 -days 3650 \
 -nodes \
 -subj /CN=localhost
WORKDIR /opt
COPY mock_proxy.py /opt
RUN chmod +x /opt/mock_proxy.py
EXPOSE 7080 7443
ENTRYPOINT ["/opt/mock_proxy.py"]
