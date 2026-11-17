# sruru アプリ（scripts/dist.sh の成果物を詰めるだけ）
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S sruru && adduser -S -G sruru sruru
COPY dist/lib /app/lib
COPY dist/static /app/static
ENV STATIC_DIR=/app/static HTTP_PORT=8080
USER sruru
EXPOSE 8080 8443
CMD ["java", "-XX:MaxRAMPercentage=70", "-cp", "/app/lib/*", "sruru.app.Main"]
