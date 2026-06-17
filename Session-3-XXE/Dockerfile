FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

ARG S3_FLAG1="flag{XXE_p4th_tr4v3rs4l_w0rks!}"
ARG S3_FLAG2="flag{XXE_SSRF_r00t_0wn3d!}"

COPY target/*.jar app.jar

RUN echo "$S3_FLAG1" > /flag.txt && chmod 644 /flag.txt

RUN echo "$S3_FLAG2" > /root/flag.txt && chmod 600 /root/flag.txt

RUN apk add --no-cache python3 sudo

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /app

RUN echo "appuser ALL=(root) NOPASSWD: /usr/bin/python3" >> /etc/sudoers

RUN printf '#!/bin/sh\n\
sudo python3 -m http.server 9090 --directory /root &\n\
exec java -jar /app/app.jar\n' > /entrypoint.sh && chmod +x /entrypoint.sh

USER appuser

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
