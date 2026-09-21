package com.pcap.storage;

import com.pcap.config.Config;
import com.pcap.model.Aggregations;
import com.pcap.model.CaptureSummary;
import com.pcap.model.ImageRecord;
import com.pcap.model.Packet;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

/**
 * Fallback storage that writes processed data to local JSON/CSV files.
 * Useful for running and validating the pipeline without a Cassandra node.
 */
public class FileStorage implements Storage {

    // Shared lock to serialize writes to the shared aggregation files across
    // concurrent file processors (Level 2).
    private static final Object FILE_LOCK = new Object();

    private final Config config;
    private Writer packetWriter;
    private int buffered;

    public FileStorage(Config config) {
        this.config = config;
    }

    @Override
    public void init() throws Exception {
        File dir = new File(config.storageFileFolder);
        dir.mkdirs();
        if (!dir.isDirectory()) {
            throw new IllegalStateException("Cannot create folder " + dir);
        }
        String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss_SSS").format(new Date())
                + "_" + java.util.UUID.randomUUID().toString().substring(0, 8);
        File f = new File(dir, "packets_" + stamp + ".json");
        packetWriter = new PrintWriter(new FileWriter(f, true));
    }

    @Override
    public void storePacket(String fileId, Packet p) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"fileId\":\"").append(fileId).append('"')
          .append(",\"index\":").append(p.index)
          .append(",\"ts\":").append(p.timestampMs)
          .append(",\"protocol\":\"").append(jsonEsc(p.protocol)).append('"')
          .append(",\"srcIp\":\"").append(jsonEsc(p.srcIp)).append('"')
          .append(",\"dstIp\":\"").append(jsonEsc(p.dstIp)).append('"')
          .append(",\"srcMac\":\"").append(jsonEsc(p.srcMac)).append('"')
          .append(",\"dstMac\":\"").append(jsonEsc(p.dstMac)).append('"')
          .append(",\"srcPort\":").append(p.srcPort)
          .append(",\"dstPort\":").append(p.dstPort)
          .append(",\"size\":").append(p.totalSize)
          .append('}');
        synchronized (this) {
            packetWriter.write(sb.toString());
            packetWriter.write('\n');
            if (++buffered >= config.dbBatchSize) {
                packetWriter.flush();
                buffered = 0;
            }
        }
    }

    @Override
    public void flush() throws Exception {
        synchronized (this) {
            packetWriter.flush();
            buffered = 0;
        }
    }

    @Override
    public void storeCapture(CaptureSummary s) throws Exception {
        File dir = new File(config.storageFileFolder);
        File f = new File(dir, "captures.json");
        StringBuilder sb = new StringBuilder();
        sb.append("{\"fileId\":\"").append(s.fileId)
          .append("\",\"fileName\":\"").append(jsonEsc(s.fileName))
          .append("\",\"packets\":").append(s.packetCount)
          .append(",\"bytes\":").append(s.byteCount)
          .append(",\"durationMs\":").append(s.getDurationMs())
          .append(",\"status\":\"").append(s.status).append("\"}");
        appendLine(f, sb.toString());
    }

    @Override
    public void storeAggregations(String fileId, Aggregations agg) throws Exception {
        File dir = new File(config.storageFileFolder);
        File f = new File(dir, "aggregations.json");
        for (Map.Entry<String, Long> e : agg.protocolCounts.entrySet()) {
            String line = "{\"fileId\":\"" + fileId + "\",\"protocol\":\"" + jsonEsc(e.getKey())
                    + "\",\"count\":" + e.getValue() + "}";
            appendLine(f, line);
        }
    }

    @Override
    public void storeImage(ImageRecord img) throws Exception {
        File dir = new File(config.storageFileFolder);
        File f = new File(dir, "images.json");
        String line = "{\"fileId\":\"" + img.fileId + "\",\"url\":\"" + jsonEsc(img.url)
                + "\",\"contentType\":\"" + jsonEsc(img.contentType)
                + "\",\"size\":" + img.size + ",\"path\":\"" + jsonEsc(img.filePath) + "\"}";
        appendLine(f, line);
    }

    @Override
    public List<Packet> search(String protocol, String ip, int limit) {
        return new ArrayList<Packet>();
    }

    @Override
    public Map<String, Long> protocolCounts() {
        return new java.util.HashMap<String, Long>();
    }

    @Override
    public void close() throws Exception {
        if (packetWriter != null) {
            packetWriter.flush();
            packetWriter.close();
        }
    }

    private static void appendLine(File f, String line) throws Exception {
        synchronized (FILE_LOCK) {
            PrintWriter w = new PrintWriter(new FileWriter(f, true));
            try {
                w.println(line);
            } finally {
                w.close();
            }
        }
    }

    private static String jsonEsc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
