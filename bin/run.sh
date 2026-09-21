#!/usr/bin/env bash
# Run script for the PCAP Processor (CentOS 7 / JDK 8).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAVA_BIN="java"
if [ -n "$JAVA_HOME" ]; then JAVA_BIN="$JAVA_HOME/bin/java"; fi

exec "$JAVA_BIN" -cp "$ROOT/build/classes" com.pcap.Application "$@"
