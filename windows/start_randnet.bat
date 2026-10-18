@echo off
rem Start the Randnet bridge with the config next to this file.
rem Extra arguments are passed through, e.g.  start_randnet.bat --verbose
cd /d "%~dp0"
py -3 randnet_win.py --config randnet_win.conf --log-file randnet_win.log %*
pause
