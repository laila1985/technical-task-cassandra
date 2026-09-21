package com.pcap.model;

/**
 * Aggregation result for one capture file (Level 3 aggregation data).
 */
public final class CaptureSummary {

    public String fileId;        // UUID string
    public String fileName;
    public long fileSize;
    public long firstTimestampMs = -1;
    public long lastTimestampMs = -1;
    public long durationMs;
    public long packetCount;
    public long byteCount;
    public long ethernetCount;
    public long ipCount;
    public long tcpCount;
    public long udpCount;
    public long otherCount;
    public String status = "PROCESSED";
    public String error;
    public long processedAt;

    public long getDurationMs() {
        if (firstTimestampMs >= 0 && lastTimestampMs >= 0) {
            return Math.max(0, lastTimestampMs - firstTimestampMs);
        }
        return 0;
    }
}
