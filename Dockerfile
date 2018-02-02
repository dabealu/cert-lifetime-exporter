FROM       alpine:3.6
COPY       cert-lifetime-exporter /usr/local/bin/cert-lifetime-exporter
RUN        apk update && apk add ca-certificates
ENTRYPOINT ["/usr/local/bin/cert-lifetime-exporter"]
CMD        ["--config", "/config.json"]