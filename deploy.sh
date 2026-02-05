#!/bin/bash

# XXE XLSX Tool - Docker Deployment Script
# Usage: ./deploy.sh [build|start|stop|restart|logs|clean]

set -e

PROJECT_NAME="xxe-xlsx-tool"
IMAGE_NAME="xxe-xlsx-tool:latest"

case "$1" in
    "build")
        echo "🔨 Building Docker image..."
        docker build -t $IMAGE_NAME .
        echo "✅ Build completed!"
        ;;
    
    "start")
        echo "🚀 Starting XXE XLSX Tool..."
        docker-compose up -d
        echo "✅ Application started at http://localhost:3000"
        ;;
    
    "stop")
        echo "🛑 Stopping XXE XLSX Tool..."
        docker-compose down
        echo "✅ Application stopped!"
        ;;
    
    "restart")
        echo "🔄 Restarting XXE XLSX Tool..."
        docker-compose down
        docker-compose up -d
        echo "✅ Application restarted!"
        ;;
    
    "logs")
        echo "📋 Showing logs..."
        docker-compose logs -f
        ;;
    
    "clean")
        echo "🧹 Cleaning up Docker resources..."
        docker-compose down -v
        docker rmi $IMAGE_NAME 2>/dev/null || true
        docker system prune -f
        echo "✅ Cleanup completed!"
        ;;
    
    "dev")
        echo "🔧 Starting development environment..."
        docker-compose --profile dev up -d
        echo "✅ Dev environment started!"
        echo "Backend: http://localhost:5000"
        echo "Frontend: http://localhost:3001"
        ;;
    
    *)
        echo "XXE XLSX Tool - Docker Deployment"
        echo ""
        echo "Usage: $0 {build|start|stop|restart|logs|clean|dev}"
        echo ""
        echo "Commands:"
        echo "  build   - Build Docker image"
        echo "  start   - Start application (http://localhost:3000)"
        echo "  stop    - Stop application"
        echo "  restart - Restart application"
        echo "  logs    - Show application logs"
        echo "  clean   - Clean up Docker resources"
        echo "  dev     - Start development environment"
        exit 1
        ;;
esac