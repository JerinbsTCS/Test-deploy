FROM eclipse-temurin:17-jre
WORKDIR /app

ARG S4_FLAG="flag{3CB_m0d3_1s_br0k3n!}"
ARG S4_SECRET="ThisIsA16ByteKey"
ENV S4_FLAG=${S4_FLAG}
ENV S4_SECRET=${S4_SECRET}

COPY ./target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
