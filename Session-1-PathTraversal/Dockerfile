FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

ARG RUN_AS_ROOT=false

ARG S1_FLAG1="flag{P4th_Tr4v3r5s4l_Bug_F0und!}"

ARG S1_FLAG2="flag{P4th_Tr4v3r5s4l_0n_r00t_15_fun}"

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
