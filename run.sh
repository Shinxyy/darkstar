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
if [ ! -f ./.env ]; then
  echo "Creating .env file..."
  cat > ./.env << EOF
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

# Setup openvas docker
echo '[+] Building the OpenVAS docker'
docker compose -f docker-compose.openvas.yaml up -d --build

# Start the custom api service
echo '[+] Starting API Service OpenVAS'
docker exec automatic-propagation-gvmd-1 /bin/sh -c "apt update && apt install python3-pip -y && python3 -m pip install gvm-tools Flask requests && python3 /opt/openvas_api.py && tail -f /dev/null" &

echo '[+] Cleaning up'
sleep 5
clear

echo '[+] Starting interactive shell inside the container'
docker exec -it darkstar /bin/bash