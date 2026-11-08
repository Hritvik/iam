# syntax=docker/dockerfile:1

FROM gradle:9.8.2-jdk25@sha256:e46e15353757ef9c9be0197a243653e88d25ebcd4c3c841057cf839c11fcf898 AS build
WORKDIR /workspace
COPY settings.gradle.kts build.gradle.kts gradle.lockfile ./
COPY gradle/verification-metadata.xml ./gradle/verification-metadata.xml
COPY src ./src
COPY contracts ./contracts
RUN gradle --no-daemon --dependency-verification=strict bootJar

FROM eclipse-temurin:25-jre-noble AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 iam \
    && useradd --system --uid 10001 --gid iam --home-dir /app --shell /usr/sbin/nologin iam

WORKDIR /app
COPY --from=build --chown=10001:10001 /workspace/build/libs/iam-0.1.0-SNAPSHOT.jar /app/application.jar

USER 10001:10001
EXPOSE 8080
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75"

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=5 \
    CMD curl --fail --silent --show-error http://localhost:8080/actuator/health/readiness || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/application.jar"]
