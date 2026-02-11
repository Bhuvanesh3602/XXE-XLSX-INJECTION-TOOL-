# 🚀 XXE XLSX Tool - One Command Setup

## For Your Friend (No Code Download Needed!)

### Prerequisites
- Docker Desktop installed
- That's it!

### Run the Tool (One Command)
```bash
docker run -d -p 3000:5000 --name xxe-tool bhuvanesh3602/xxe-xlsx-tool
```

### Access the Application
- Open browser: http://localhost:3000
- Upload XLSX files and test XXE vulnerabilities

### Commands
```bash
# Start
docker run -d -p 3000:5000 --name xxe-tool bhuvanesh3602/xxe-xlsx-tool

# Stop
docker stop xxe-tool

# Remove
docker rm xxe-tool

# View logs
docker logs xxe-tool

# Restart
docker restart xxe-tool
```

### Alternative Port (if 3000 is busy)
```bash
docker run -d -p 8080:5000 --name xxe-tool bhuvanesh3602/xxe-xlsx-tool
# Access at: http://localhost:8080
```

## That's it! No code download required! 🎉