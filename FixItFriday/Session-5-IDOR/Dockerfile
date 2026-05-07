FROM eclipse-temurin:17-jre
WORKDIR /app

ARG S5_FLAG="flag{1D0R_0rd3r_l34k_sh0p3z!}"
ENV S5_FLAG=${S5_FLAG}

COPY ./target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
