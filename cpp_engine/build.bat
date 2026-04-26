@echo off
REM Build script for Windows

echo Installing pybind11...
python -m pip install pybind11

echo Creating build directory...
if not exist build mkdir build
cd build

echo Running CMake...
cmake .. -G "Visual Studio 17 2022" -A x64

echo Building...
cmake --build . --config Release

echo Copying module to backend...
copy Release\covert_engine*.pyd ..\..\backend\

echo Build complete!
cd ..
