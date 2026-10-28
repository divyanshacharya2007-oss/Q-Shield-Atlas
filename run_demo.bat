@echo off
setlocal
pushd "%~dp0"

set "PYTHON=python"
if exist ".venv\Scripts\activate.bat" (
  call ".venv\Scripts\activate.bat"
  set "PYTHON=python"
) else if exist ".venv\Scripts\python.exe" (
  set "PYTHON=.venv\Scripts\python.exe"
) else (
  py -3.12 -c "import sys; print(sys.version)" >nul 2>nul
  if errorlevel 1 (
    echo Python 3.12 or newer is required. Create .venv and install requirements.txt.
    popd
    exit /b 1
  )
  set "PYTHON=py -3.12"
)

%PYTHON% -c "import sys; sys.version_info >= (3, 12) or sys.exit('Python 3.12+ is required')"
if errorlevel 1 (popd & exit /b 1)
%PYTHON% -m pip --version >nul
if errorlevel 1 (popd & exit /b 1)
%PYTHON% run_demo.py
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%