FROM maven:3.9.11-eclipse-temurin-25 AS build
WORKDIR /workspace
COPY . .
RUN --mount=type=cache,target=/root/.m2 mvn -pl security-core -am package -DskipTests

FROM eclipse-temurin:25-jre
WORKDIR /app
RUN addgroup --system securelayer && adduser --system --ingroup securelayer securelayer
COPY --from=build /workspace/security-core/target/security-core-*.jar /app/security-core.jar
USER securelayer
EXPOSE 8090 9090
ENTRYPOINT ["java", "-jar", "/app/security-core.jar"]
