#!/bin/bash
set -e

echo "Installing dependencies..."
npm ci --only=production

echo "Building React app..."
npx react-scripts build

echo "Build completed successfully!"