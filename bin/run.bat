@echo off
REM Run script for the PCAP Processor (Windows dev convenience).
setlocal
set "ROOT=%~dp0.."
if defined JAVA_HOME (
    set "JAVA_BIN=%JAVA_HOME%\bin\java.exe"
) else (
    set "JAVA_BIN=java"
)
"%JAVA_BIN%" -cp "%ROOT%\build\classes" com.pcap.Application %*
endlocal
