package com.pcap.process;

import com.pcap.config.Config;
import com.pcap.extract.ImageExtractor;
import com.pcap.model.Aggregations;
import com.pcap.model.CaptureSummary;
import com.pcap.model.Packet;
import com.pcap.parser.PcapParser;
import com.pcap.stats.Statistics;
import com.pcap.storage.Storage;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.UUID;

/**
 * Parses a single PCAP file and streams decoded packets to the storage
 * backend while accumulating aggregation data (Level 1 / 2 / 3).
 *
 * Each file is processed by its own thread and owns its own Storage
 * connection, so concurrent files never share mutable client state.
 */
public final class FileProcessor implements Runnable {

    private final File file;
    private final Config config;
    private final Storage storage;
    private final Statistics statistics;

    private volatile boolean done = false;
    private volatile String status = "PROCESSED";
    private volatile String error = null;
    private volatile CaptureSummary summary;

    public FileProcessor(File file, Config config, Storage storage, Statistics statistics) {
        this.file = file;
        this.config = config;
        this.storage = storage;
        this.statistics = statistics;
    }

    @Override
    public void run() {
        String fileId = UUID.randomUUID().toString();
        CaptureSummary s = new CaptureSummary();
        s.fileId = fileId;
        s.fileName = file.getName();
        s.fileSize = file.length();
        s.processedAt = System.currentTimeMillis();

        Aggregations agg = new Aggregations();
        ImageExtractor extractor = new ImageExtractor(config, storage);

        long packets = 0;
        final long[] bytesHolder = new long[1];

        FileInputStream fis = null;
        try {
            storage.init();
            fis = new FileInputStream(file);
            BufferedInputStream bis = new BufferedInputStream(fis, 64 * 1024);
            PcapParser parser = new PcapParser(bis);
            parser.readGlobalHeader();

            packets = parser.parse(new PcapParser.PacketHandler() {
                @Override
                public boolean onPacket(Packet p) throws Exception {
                    if (s.firstTimestampMs < 0) {
                        s.firstTimestampMs = p.timestampMs;
                    }
                    s.lastTimestampMs = p.timestampMs;
                    bytesHolder[0] += p.wireLen;

                    // protocol counters
                    String proto = p.protocol == null ? "UNKNOWN" : p.protocol;
                    agg.addProtocol(proto);
                    if ("ETHERNET".equals(proto) || p.srcMac != null) s.ethernetCount++;
                    if (p.srcIp != null) s.ipCount++;
                    if ("TCP".equals(proto)) s.tcpCount++;
                    else if ("UDP".equals(proto)) s.udpCount++;
                    else if (p.srcIp == null) s.otherCount++;

                    agg.addIpPair(p.srcIp, p.dstIp, p.wireLen);
                    agg.addEndpoint(p.srcIp, p.srcMac, true, p.wireLen);
                    agg.addEndpoint(p.dstIp, p.dstMac, false, p.wireLen);

                    // Level 5: image extraction
                    if (p.httpContentType != null) {
                        if (extractor.handle(p, fileId) > 0) {
                            statistics.onImageExtracted();
                        }
                    }

                    storage.storePacket(fileId, p);
                    statistics.onPacketsInserted(1);
                    return true;
                }
            });

            statistics.onPacketsParsed(packets);
            storage.flush();
        } catch (Exception e) {
            status = "FAILED";
            error = e.toString();
            System.err.println("[processor] FAILED " + file.getName() + ": " + e);
            statistics.onFileFailed();
            done = true;
            summary = s;
            summary.status = status;
            summary.error = error;
            summary.packetCount = packets;
            summary.byteCount = bytesHolder[0];
            try { storage.flush(); } catch (Exception ignore) { }
            try { storage.storeCapture(summary); } catch (Exception ignore) { }
            try { storage.close(); } catch (Exception ignore) { }
            return;
        } finally {
            if (fis != null) {
                try { fis.close(); } catch (Exception ignore) { }
            }
        }

        s.packetCount = packets;
        s.byteCount = bytesHolder[0];
        s.durationMs = s.getDurationMs();
        s.status = status;
        summary = s;

        try {
            storage.storeAggregations(fileId, agg);
            storage.storeCapture(s);
        } catch (Exception e) {
            status = "FAILED";
            error = e.toString();
            statistics.onFileFailed();
        }

        statistics.onFileProcessed();
        done = true;
        try { storage.close(); } catch (Exception ignore) { }

        moveFile(file, config.processedFolder);
    }

    public boolean isDone() { return done; }
    public String getStatus() { return status; }
    public String getError() { return error; }
    public CaptureSummary getSummary() { return summary; }

    private static void moveFile(File f, String folder) {
        if (folder == null || folder.trim().isEmpty()) {
            return;
        }
        File dir = new File(folder);
        if (!dir.exists() && !dir.mkdirs()) {
            return;
        }
        File dest = new File(dir, f.getName());
        if (dest.exists()) {
            dest = new File(dir, System.currentTimeMillis() + "_" + f.getName());
        }
        try {
            if (!f.renameTo(dest)) {
                java.nio.file.Files.move(f.toPath(), dest.toPath(),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (Exception ignore) {
        }
    }
}
