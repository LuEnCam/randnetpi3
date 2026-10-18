@echo off
rem Start the Randnet bridge on Windows XP with randnet_xp.conf.
rem Extra arguments are passed through, e.g.  start_randnet_xp.bat --verbose
cd /d "%~dp0"
set PY=C:\Python34\python.exe
if not exist "%PY%" set PY=py -3.4
%PY% randnet_xp.py --log-file randnet_xp.log %*
pause
