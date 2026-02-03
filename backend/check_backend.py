import subprocess
import time
import requests
import sys

def check_backend():
    try:
        response = requests.get("http://localhost:5000/api/health", timeout=2)
        return response.status_code == 200
    except:
        return False

def start_backend():
    print("Backend not running. Starting...")
    subprocess.Popen([sys.executable, "app.py"], cwd=".")
    
    # Wait for backend to start
    for i in range(10):
        time.sleep(1)
        if check_backend():
            print("✅ Backend started successfully!")
            return True
        print(f"Waiting... ({i+1}/10)")
    
    print("❌ Failed to start backend")
    return False

if __name__ == "__main__":
    if not check_backend():
        if not start_backend():
            exit(1)
    
    print("✅ Backend is running on http://localhost:5000")
    print("Health check: http://localhost:5000/api/health")