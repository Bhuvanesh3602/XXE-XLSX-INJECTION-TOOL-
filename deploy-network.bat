@echo off
echo ========================================
echo XXE XLSX Tool - Network Deployment
echo ========================================
echo.

REM Get local IP address
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do (
    for /f "tokens=1" %%b in ("%%a") do (
        set LOCAL_IP=%%b
        goto :found
    )
)
:found

echo Your local IP address: %LOCAL_IP%
echo.
echo Others can access your application at:
echo - Frontend: http://%LOCAL_IP%:3000
echo - Backend API: http://%LOCAL_IP%:5000
echo.

REM Install dependencies
echo Installing backend dependencies...
cd backend
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Failed to install backend dependencies
    pause
    exit /b 1
)

echo Installing frontend dependencies...
cd ..\frontend
call npm install
if %errorlevel% neq 0 (
    echo Failed to install frontend dependencies
    pause
    exit /b 1
)

echo.
echo Setting up network configuration...
set REACT_APP_API_URL=http://%LOCAL_IP%:5000

echo.
echo Starting servers for network access...
echo.

REM Start backend
cd ..\backend
start "XXE Backend (Network)" cmd /k "echo Backend running on http://%LOCAL_IP%:5000 && python app.py"

REM Wait for backend to start
timeout /t 5 /nobreak >nul

REM Start frontend with network configuration
cd ..\frontend
start "XXE Frontend (Network)" cmd /k "echo Frontend running on http://%LOCAL_IP%:3000 && set REACT_APP_API_URL=http://%LOCAL_IP%:5000 && npm start"

echo.
echo ========================================
echo Network Deployment Complete!
echo ========================================
echo.
echo Share these URLs with others on your network:
echo - Application: http://%LOCAL_IP%:3000
echo - API Health: http://%LOCAL_IP%:5000/api/health
echo.
echo Make sure Windows Firewall allows connections on ports 3000 and 5000
echo.
pause