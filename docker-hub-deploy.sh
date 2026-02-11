#!/bin/bash
# Deploy Docker container to Docker Hub

# Build and tag image
docker build -t your-username/xxe-xlsx-tool .

# Push to Docker Hub
docker push your-username/xxe-xlsx-tool

# Your friend can run:
# docker run -p 3000:5000 your-username/xxe-xlsx-tool