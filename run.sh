#!/bin/bash

# Default values for the .env file
ROOT_PASSWORD="database_is_fun01"
DB_HOST="mariadb"
DB_NAME="test"
DB_USER="data_guru"
DB_PASSWORD="kjafskljfs836487348akskdhkasdhk"
HIBP_KEY=""
OPENVAS_USER=""
OPENVAS_PASSWORD=""

# Check if .env file exists, if not create it
if [ ! -f ./darkstar/.env ]; then
  echo "Creating .env file..."
  cat > ./darkstar/.env << EOF
# Database credentials for MariaDB and Python
MYSQL_ROOT_PASSWORD=${ROOT_PASSWORD}
DB_HOST=${DB_HOST}
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}

# HIBP
HIBP_KEY=${HIBP_KEY}

# OpenVAS
OPENVAS_USER=${OPENVAS_USER}
OPENVAS_PASSWORD=${OPENVAS_PASSWORD}
EOF
fi

# Enabling BuildKit for faster builds
export DOCKER_BUILDKIT=1

# Setup the docker
echo '[+] Building the Darkstar docker with all the tools inside'
docker compose -f docker-compose.yaml up -d --build

# Wait briefly to ensure containers have time to start properly
echo '[+] Waiting for containers to initialize...'
sleep 10

# Remove redundant command since we added tail -f /dev/null to docker-compose.yaml
# docker exec darkstar bash -c "nohup tail -f /dev/null > /dev/null 2>&1 &"

# Setup openvas docker
# echo '[+] Building the OpenVAS docker'
# docker compose -f docker-compose.openvas.yaml up -d --build

# Start the custom api service
# echo '[+] Starting API Service OpenVAS'
# docker exec greenbone-community-edition-gvmd-1 /bin/sh -c "apt update && apt install python3-pip procps -y && python3 -m pip install gvm-tools Flask requests --break-system-packages && python3 /opt/openvas_api.py && tail -f /dev/null" &

echo '[+] Cleaning up'
sleep 5

# More robust container status check
echo '[+] Checking if darkstar container is running...'
if [ "$(docker inspect -f '{{.State.Running}}' darkstar 2>/dev/null)" == "true" ]; then
  echo '[+] Starting interactive shell inside the container'
  docker exec -it darkstar /bin/bash
else
  echo '[!] Error: The darkstar container is not running. Cannot start interactive shell.'
  echo '[!] Attempting to restart the container...'
  docker compose -f docker-compose.yaml restart darkstar
  sleep 5
  
  # Check again after restart attempt
  if [ "$(docker inspect -f '{{.State.Running}}' darkstar 2>/dev/null)" == "true" ]; then
    echo '[+] Container restarted successfully. Starting interactive shell.'
    docker exec -it darkstar /bin/bash
  else
    echo '[!] Failed to restart container. Check the logs with: docker logs darkstar'
  fi
fi