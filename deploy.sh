#!/bin/bash
set -e

cd /opt/responseray

# Create .env if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    # Generate a random password
    PASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)
    sed -i "s/changeme_in_production/$PASS/g" .env
    echo "Generated .env with password: $PASS"
    echo "SAVE THIS PASSWORD - you need it to log in"
fi

# Build and start
docker compose build --no-cache
docker compose up -d

echo ""
echo "ResponseRay is starting..."
echo "Waiting for services to be healthy..."
sleep 10
docker compose ps
echo ""
echo "ResponseRay is running on http://localhost:80"
