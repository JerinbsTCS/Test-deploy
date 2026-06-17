FROM eclipse-temurin:17-jre
WORKDIR /app

ARG S2_FLAG="flag{SQLi_15_4w350m3!!}"
ENV S2_FLAG=${S2_FLAG}

COPY ./target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
