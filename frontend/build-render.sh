#!/bin/bash
set -e

echo "Installing dependencies..."
npm install

echo "Fixing permissions..."
chmod +x node_modules/.bin/react-scripts

echo "Building React app..."
npm run build

echo "Build completed successfully!"