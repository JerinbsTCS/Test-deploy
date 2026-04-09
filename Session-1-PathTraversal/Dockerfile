FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

ARG APP_USER=appuser

ARG S1_FLAG1="flag{P4th_Tr4v3rs4l_1s_4w3s0m3}"

ARG S1_FLAG2="flag{P4th_Tr4v3rs4l_1s_4w3s0m3_but_d0n7_3xpl01t_1t}"

COPY target/*.jar app.jar

RUN echo "$S1_FLAG1" > /flag.txt

RUN echo "$S1_FLAG2" > /root/flag.txt

RUN chmod 600 /root/flag.txt

RUN mkdir -p /app/src/main/resources/static && echo "This is a safe file." > /app/src/main/resources/static/public.txt

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

RUN chown -R appuser:appgroup /app

USER ${APP_USER}

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
