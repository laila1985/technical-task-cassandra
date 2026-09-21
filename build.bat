@echo off
REM Build script for the PCAP Processor (no Maven / Gradle).
REM Requirements: JDK 8, javac + jar on PATH.
setlocal

if defined JAVA_HOME (
    set "JAVAC=%JAVA_HOME%\bin\javac.exe"
    set "JAR=%JAVA_HOME%\bin\jar.exe"
) else (
    set "JAVAC=javac"
    set "JAR=jar"
)

set "ROOT=%~dp0"
set "SRC=%ROOT%src"
set "OUT=%ROOT%build\classes"

if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"

dir /s /b "%SRC%\*.java" > "%ROOT%build\sources.txt"
"%JAVAC%" -encoding UTF-8 -source 1.8 -target 1.8 -d "%OUT%" @"%ROOT%build\sources.txt"
if errorlevel 1 exit /b 1

echo Compilation successful. Classes in %OUT%
echo Run with:  bin\run.bat
endlocal
