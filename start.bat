@echo off
echo Starting XXE XLSX Tool...
echo.

REM Check if backend directory exists
if not exist "backend" (
    echo Error: backend directory not found
    pause
    exit /b 1
)

REM Check if frontend directory exists
if not exist "frontend" (
    echo Error: frontend directory not found
    pause
    exit /b 1
)

echo Installing dependencies...
cd backend
pip install Flask Flask-CORS Werkzeug requests
cd ..\frontend
call npm install
cd ..

echo.
echo Starting servers...
echo Backend will start on: http://localhost:5000
echo Frontend will start on: http://localhost:3000
echo.

REM Start backend in new window
start "XXE Backend" cmd /k "cd backend && python app.py"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend in new window
start "XXE Frontend" cmd /k "cd frontend && npm start"

echo.
echo Both servers are starting...
echo.
echo Test URLs:
echo - Backend Health: http://localhost:5000/api/health
echo - Frontend App: http://localhost:3000
echo.
echo Press any key to close this window...
pause >nul