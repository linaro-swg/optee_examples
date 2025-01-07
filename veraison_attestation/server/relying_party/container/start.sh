#!/bin/bash
set -euo pipefail

IMAGE_NAME="optee-ra-relying-party"
TAG="latest"

SCRIPT_DIR=$(dirname "$(realpath "$0")")

if ! command -v docker &> /dev/null
then
    echo "Error: Docker is not installed. Please install Docker and try again."
    exit 1
fi

if ! docker info &> /dev/null
then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "Building Docker image..."
docker build -t ${IMAGE_NAME}:${TAG} \
             --build-arg USER_UID=$(id -u) \
             --build-arg USER_GID=$(id -g) \
             -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}/.."

echo "Docker image ${IMAGE_NAME}:${TAG} has been successfully built."

echo "Running Docker container..."
docker run --rm -d \
           --network veraison-net \
           -p 8087:8087 \
           --name relying-party-service \
           -v "${SCRIPT_DIR}/../app:/app" \
           ${IMAGE_NAME}:${TAG}

echo "Docker container has been successfully run."
