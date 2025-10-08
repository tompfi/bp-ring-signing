FROM debian:bullseye

RUN apt-get update && \
    apt-get install -y tor && \
    mkdir -p /var/lib/tor/hidden_service && \
    chown -R debian-tor:debian-tor /var/lib/tor

COPY torrc /etc/tor/torrc

CMD ["tor", "-f", "/etc/tor/torrc"]