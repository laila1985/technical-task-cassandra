# Multi-stage build for the PCAP Processor (CentOS 7 compatible, Java 8).
# Stage 1: compile with JDK 8 (no Maven / Gradle - plain javac).
# Stage 2: run with a slim JRE 8 image.

# ---------- Build stage ----------
FROM eclipse-temurin:8-jdk AS build

WORKDIR /build

COPY src ./src

# Compile all sources targeting Java 8.
RUN find src -name '*.java' > sources.txt && \
    mkdir -p classes && \
    javac -encoding UTF-8 -source 1.8 -target 1.8 -d classes @sources.txt

# ---------- Runtime stage ----------
FROM eclipse-temurin:8-jre

WORKDIR /app

COPY --from=build /build/classes ./classes
COPY conf ./conf

# Volumes for input PCAP files and output (images / file-storage fallback).
VOLUME ["/app/input", "/app/output"]

ENTRYPOINT ["java", "-cp", "classes", "com.pcap.Application"]
CMD ["--config", "conf/application.properties"]
