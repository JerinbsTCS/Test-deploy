FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

ARG RUN_AS_ROOT=false

ARG S1_FLAG1

ARG S1_FLAG2

COPY target/*.jar app.jar

RUN echo "$S1_FLAG1" > /flag.txt

RUN echo "$S1_FLAG2" > /root/flag.txt

RUN mkdir -p /app/src/main/resources/static && echo "This is a safe file." > /app/src/main/resources/static/public.txt

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

RUN chown -R appuser:appgroup /app

USER ${RUN_AS_ROOT#true} root
USER ${RUN_AS_ROOT#false} appuser

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
