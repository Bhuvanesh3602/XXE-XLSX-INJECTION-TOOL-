# Docker Deployment Commands

# After Docker Desktop is running:

# Option 1: Simple Backend Only
docker-compose -f docker-compose.simple.yml up -d --build

# Option 2: Full Application
docker-compose up -d --build

# Check running containers
docker ps

# View logs
docker-compose logs -f

# Stop application
docker-compose down

# Clean up
docker system prune -f