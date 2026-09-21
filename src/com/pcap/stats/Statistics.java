package com.pcap.stats;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Global statistics: processed/failed files, parsed/inserted records and
 * records-per-second performance metrics (Level 1).
 */
public final class Statistics {

    private final AtomicLong filesProcessed = new AtomicLong();
    private final AtomicLong filesFailed = new AtomicLong();
    private final AtomicLong packetsParsed = new AtomicLong();
    private final AtomicLong packetsInserted = new AtomicLong();
    private final AtomicLong imagesExtracted = new AtomicLong();

    private final long startTime = System.currentTimeMillis();

    // previous sample for rate calculation
    private volatile long lastSampleTime = startTime;
    private volatile long lastParsed = 0;
    private volatile long lastInserted = 0;

    public void onFileProcessed() { filesProcessed.incrementAndGet(); }
    public void onFileFailed() { filesFailed.incrementAndGet(); }
    public void onPacketsParsed(long n) { packetsParsed.addAndGet(n); }
    public void onPacketsInserted(long n) { packetsInserted.addAndGet(n); }
    public void onImageExtracted() { imagesExtracted.incrementAndGet(); }

    public long getFilesProcessed() { return filesProcessed.get(); }
    public long getFilesFailed() { return filesFailed.get(); }
    public long getPacketsParsed() { return packetsParsed.get(); }
    public long getPacketsInserted() { return packetsInserted.get(); }
    public long getImagesExtracted() { return imagesExtracted.get(); }

    /** Returns a snapshot including records/sec processed and inserted. */
    public Snapshot snapshot() {
        long now = System.currentTimeMillis();
        long elapsedTotal = Math.max(1, now - startTime);
        long elapsedSince = Math.max(1, now - lastSampleTime);

        long totalParsed = packetsParsed.get();
        long totalInserted = packetsInserted.get();

        double parsedRate = (totalParsed - lastParsed) * 1000.0 / elapsedSince;
        double insertedRate = (totalInserted - lastInserted) * 1000.0 / elapsedSince;

        lastSampleTime = now;
        lastParsed = totalParsed;
        lastInserted = totalInserted;

        return new Snapshot(
                filesProcessed.get(), filesFailed.get(),
                totalParsed, totalInserted, imagesExtracted.get(),
                parsedRate, insertedRate, elapsedTotal);
    }

    public static final class Snapshot {
        public final long filesProcessed;
        public final long filesFailed;
        public final long packetsParsed;
        public final long packetsInserted;
        public final long imagesExtracted;
        public final double recordsPerSecParsed;
        public final double recordsPerSecInserted;
        public final long uptimeMs;

        Snapshot(long fp, long ff, long pp, long pi, long ie,
                 double pps, double ips, long up) {
            this.filesProcessed = fp;
            this.filesFailed = ff;
            this.packetsParsed = pp;
            this.packetsInserted = pi;
            this.imagesExtracted = ie;
            this.recordsPerSecParsed = pps;
            this.recordsPerSecInserted = ips;
            this.uptimeMs = up;
        }

        public String toString() {
            return String.format(
                    "files[processed=%d failed=%d] packets[parsed=%d inserted=%d images=%d] "
                            + "perf[%.1f rec/s parsed, %.1f rec/s inserted]",
                    filesProcessed, filesFailed, packetsParsed, packetsInserted, imagesExtracted,
                    recordsPerSecParsed, recordsPerSecInserted);
        }
    }
}
