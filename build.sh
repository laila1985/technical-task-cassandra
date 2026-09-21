#!/usr/bin/env bash
# Build script for the PCAP Processor (no Maven / Gradle).
# Requirements: JDK 8, javac + jar on PATH.
set -e

JAVA_HOME="${JAVA_HOME:-}"
if [ -n "$JAVA_HOME" ]; then
    JAVAC="$JAVA_HOME/bin/javac"
    JAR="$JAVA_HOME/bin/jar"
else
    JAVAC="javac"
    JAR="jar"
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/src"
OUT="$ROOT/build/classes"
DIST="$ROOT/build/dist"

rm -rf "$OUT"
mkdir -p "$OUT"

# Compile all sources with JDK 8 target.
find "$SRC" -name '*.java' > "$ROOT/build/sources.txt"
"$JAVAC" -encoding UTF-8 -source 1.8 -target 1.8 -d "$OUT" @"$ROOT/build/sources.txt"

# Copy non-java resources (config is kept separately in ./conf).
mkdir -p "$DIST"
cp -r "$OUT" "$DIST/classes" 2>/dev/null || true

echo "Compilation successful. Classes in $OUT"
echo "Run with:  bin/run.sh"
