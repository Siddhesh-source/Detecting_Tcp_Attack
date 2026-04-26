@echo off
echo Building C++ engine...
python setup.py build_ext --inplace

echo Copying module to backend...
if exist covert_engine*.pyd copy covert_engine*.pyd ..\backend\
if exist build\lib.win-amd64-*\covert_engine*.pyd copy build\lib.win-amd64-*\covert_engine*.pyd ..\backend\

echo Build complete!
pause
