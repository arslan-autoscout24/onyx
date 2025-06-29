docker compose \
    -f docker-compose.dev.yml \
    -f docker-compose.oauth.yml \
    -p onyx-stack up -d --build --force-recreate