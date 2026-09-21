package com.pcap.storage;

import com.pcap.cassandra.CassandraClient;
import com.pcap.config.Config;
import com.pcap.model.Aggregations;
import com.pcap.model.CaptureSummary;
import com.pcap.model.ImageRecord;
import com.pcap.model.Packet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Cassandra storage backend (Level 3). Uses the hand-written
 * {@link CassandraClient} to speak the CQL native protocol directly.
 *
 * Packets are buffered and flushed in batches (db.batch.size) for throughput.
 */
public class CassandraStorage implements Storage {

    private static final class Buf {
        final String fileId;
        final Packet packet;
        Buf(String f, Packet p) { this.fileId = f; this.packet = p; }
    }

    private final Config config;
    private CassandraClient client;
    private final List<Buf> buffer = new ArrayList<Buf>();

    // Schema creation must happen exactly once per JVM: concurrent
    // "CREATE TABLE IF NOT EXISTS" from multiple threads can race in Cassandra
    // 3 and produce "Column family ID mismatch" errors.
    private static final Object SCHEMA_LOCK = new Object();
    private static volatile boolean schemaReady = false;

    public CassandraStorage(Config config) {
        this.config = config;
    }

    @Override
    public void init() throws Exception {
        client = new CassandraClient(
                config.cassandraContactPoints,
                config.cassandraPort,
                config.cassandraUsername,
                config.cassandraPassword);
        client.setConsistency(config.cassandraConsistency);

        // Retry connection to tolerate Cassandra still starting up (e.g. in
        // Docker Compose where the app may come up before Cassandra is ready).
        int retries = Math.max(0, config.cassandraConnectRetries);
        for (int attempt = 0; ; attempt++) {
            try {
                client.connect();
                break;
            } catch (Exception e) {
                if (attempt >= retries) {
                    throw new IllegalStateException(
                            "Failed to connect to Cassandra at " + config.cassandraContactPoints
                                    + ":" + config.cassandraPort + " after " + (attempt + 1) + " attempts", e);
                }
                System.out.println("[cassandra] not ready yet (" + e.getMessage()
                        + "), retrying in " + config.cassandraConnectRetryDelayMs + "ms...");
                try {
                    Thread.sleep(config.cassandraConnectRetryDelayMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Interrupted while connecting to Cassandra", ie);
                }
            }
        }

        String ks = config.cassandraKeyspace;
        ensureSchema(ks);
    }

    private void ensureSchema(String ks) throws Exception {
        synchronized (SCHEMA_LOCK) {
            if (schemaReady) {
                return;
            }
            client.executeSimple("CREATE KEYSPACE IF NOT EXISTS " + ks
                    + " WITH replication = {'class':'SimpleStrategy','replication_factor':"
                    + config.cassandraReplicationFactor + "}");

            client.executeSimple("CREATE TABLE IF NOT EXISTS " + ks + ".captures ("
                    + "file_id uuid PRIMARY KEY, file_name text, file_size bigint,"
                    + " first_ts timestamp, last_ts timestamp, duration_ms bigint,"
                    + " packet_count bigint, byte_count bigint, ethernet_count bigint,"
                    + " ip_count bigint, tcp_count bigint, udp_count bigint, other_count bigint,"
                    + " status text, error text, processed_at timestamp)");

            client.executeSimple("CREATE TABLE IF NOT EXISTS " + ks + ".packets ("
                    + "file_id uuid, packet_index bigint, timestamp timestamp, protocol text,"
                    + " src_mac text, dst_mac text, ether_type text, src_ip text, dst_ip text,"
                    + " ip_protocol int, src_port int, dst_port int, tcp_flags text,"
                    + " seq bigint, ack bigint, payload_size int, total_size int,"
                    + " http_host text, http_uri text, http_method text, http_status int,"
                    + " http_content_type text, PRIMARY KEY (file_id, packet_index))");

            client.executeSimple("CREATE TABLE IF NOT EXISTS " + ks + ".protocols ("
                    + "file_id uuid, protocol text, count bigint, PRIMARY KEY (file_id, protocol))");

            client.executeSimple("CREATE TABLE IF NOT EXISTS " + ks + ".ip_pairs ("
                    + "file_id uuid, src_ip text, dst_ip text, packet_count bigint, byte_count bigint,"
                    + " first_ts timestamp, last_ts timestamp, PRIMARY KEY (file_id, src_ip, dst_ip))");

            client.executeSimple("CREATE TABLE IF NOT EXISTS " + ks + ".endpoints ("
                    + "file_id uuid, ip text, mac text, packets_in bigint, packets_out bigint,"
                    + " bytes_in bigint, bytes_out bigint, first_ts timestamp, last_ts timestamp,"
                    + " PRIMARY KEY (file_id, ip))");

            client.executeSimple("CREATE TABLE IF NOT EXISTS " + ks + ".images ("
                    + "file_id uuid, image_id uuid, src_ip text, dst_ip text, url text,"
                    + " content_type text, size bigint, file_path text, extracted_at timestamp,"
                    + " PRIMARY KEY (file_id, image_id))");

            createIndexIfMissing(ks, "packets", "protocol");
            createIndexIfMissing(ks, "packets", "src_ip");
            createIndexIfMissing(ks, "packets", "dst_ip");
            createIndexIfMissing(ks, "protocols", "protocol");
            createIndexIfMissing(ks, "endpoints", "ip");

            schemaReady = true;
        }
    }

    private void createIndexIfMissing(String ks, String table, String column) {
        try {
            client.executeSimple("CREATE INDEX IF NOT EXISTS idx_" + table + "_" + column
                    + " ON " + ks + "." + table + " (" + column + ")");
        } catch (Exception ignore) {
            // Non-fatal: the search UI will simply not use this index.
        }
    }

    @Override
    public void storePacket(String fileId, Packet p) throws Exception {
        buffer.add(new Buf(fileId, p));
        if (buffer.size() >= config.dbBatchSize) {
            flush();
        }
    }

    @Override
    public void flush() throws Exception {
        if (buffer.isEmpty()) {
            return;
        }
        String ks = config.cassandraKeyspace;
        String prefix = "INSERT INTO " + ks + ".packets "
                + "(file_id,packet_index,timestamp,protocol,src_mac,dst_mac,ether_type,"
                + "src_ip,dst_ip,ip_protocol,src_port,dst_port,tcp_flags,seq,ack,"
                + "payload_size,total_size,http_host,http_uri,http_method,http_status,http_content_type) "
                + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        List<Buf> toWrite = new ArrayList<Buf>(buffer);
        buffer.clear();
        for (Buf b : toWrite) {
            Packet p = b.packet;
            client.execute(prefix,
                    UUID.fromString(b.fileId),
                    p.index,
                    p.timestampMs,
                    p.protocol,
                    p.srcMac,
                    p.dstMac,
                    p.etherType,
                    p.srcIp,
                    p.dstIp,
                    p.ipProtocol,
                    p.srcPort < 0 ? null : p.srcPort,
                    p.dstPort < 0 ? null : p.dstPort,
                    p.tcpFlags,
                    p.seq < 0 ? null : p.seq,
                    p.ack < 0 ? null : p.ack,
                    p.payloadSize,
                    p.totalSize,
                    p.httpHost,
                    p.httpUri,
                    p.httpMethod,
                    p.httpStatus < 0 ? null : p.httpStatus,
                    p.httpContentType);
        }
    }

    @Override
    public void storeCapture(CaptureSummary s) throws Exception {
        String ks = config.cassandraKeyspace;
        client.execute("INSERT INTO " + ks + ".captures "
                + "(file_id,file_name,file_size,first_ts,last_ts,duration_ms,packet_count,"
                + "byte_count,ethernet_count,ip_count,tcp_count,udp_count,other_count,"
                + "status,error,processed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                UUID.fromString(s.fileId),
                s.fileName,
                s.fileSize,
                s.firstTimestampMs < 0 ? null : s.firstTimestampMs,
                s.lastTimestampMs < 0 ? null : s.lastTimestampMs,
                s.getDurationMs(),
                s.packetCount,
                s.byteCount,
                s.ethernetCount,
                s.ipCount,
                s.tcpCount,
                s.udpCount,
                s.otherCount,
                s.status,
                s.error,
                s.processedAt);
    }

    @Override
    public void storeAggregations(String fileId, Aggregations agg) throws Exception {
        String ks = config.cassandraKeyspace;
        UUID fid = UUID.fromString(fileId);

        for (Map.Entry<String, Long> e : agg.protocolCounts.entrySet()) {
            client.execute("INSERT INTO " + ks + ".protocols (file_id,protocol,count) VALUES (?,?,?)",
                    fid, e.getKey(), e.getValue());
        }
        for (Map.Entry<String, long[]> e : agg.ipPairs.entrySet()) {
            String[] parts = e.getKey().split("->", 2);
            long[] v = e.getValue();
            client.execute("INSERT INTO " + ks + ".ip_pairs "
                    + "(file_id,src_ip,dst_ip,packet_count,byte_count) VALUES (?,?,?,?,?)",
                    fid, parts[0], parts[1], v[0], v[1]);
        }
        for (Map.Entry<String, long[]> e : agg.endpoints.entrySet()) {
            long[] v = e.getValue();
            client.execute("INSERT INTO " + ks + ".endpoints "
                    + "(file_id,ip,packets_in,packets_out,bytes_in,bytes_out) VALUES (?,?,?,?,?,?)",
                    fid, e.getKey(), v[0], v[1], v[2], v[3]);
        }
    }

    @Override
    public void storeImage(ImageRecord img) throws Exception {
        String ks = config.cassandraKeyspace;
        client.execute("INSERT INTO " + ks + ".images "
                + "(file_id,image_id,src_ip,dst_ip,url,content_type,size,file_path,extracted_at) "
                + "VALUES (?,?,?,?,?,?,?,?,?)",
                UUID.fromString(img.fileId),
                UUID.fromString(img.imageId),
                img.srcIp,
                img.dstIp,
                img.url,
                img.contentType,
                img.size,
                img.filePath,
                img.extractedAt);
    }

    @Override
    public List<Packet> search(String protocol, String ip, int limit) throws Exception {
        String ks = config.cassandraKeyspace;
        StringBuilder cql = new StringBuilder("SELECT * FROM " + ks + ".packets WHERE ");
        List<Object> args = new ArrayList<Object>();
        List<String> conds = new ArrayList<String>();

        if (protocol != null && !protocol.trim().isEmpty()) {
            conds.add("protocol = ?");
            args.add(protocol.trim());
        }
        if (ip != null && !ip.trim().isEmpty()) {
            conds.add("src_ip = ?");
            args.add(ip.trim());
        }
        if (conds.isEmpty()) {
            cql = new StringBuilder("SELECT * FROM " + ks + ".packets");
        } else {
            cql.append(String.join(" AND ", conds));
        }
        // Secondary-indexed columns queried without the partition key require
        // ALLOW FILTERING in Cassandra.
        cql.append(" LIMIT ").append(Math.max(1, Math.min(limit, 1000)));
        if (!conds.isEmpty()) {
            cql.append(" ALLOW FILTERING");
        }

        CassandraClient.ResultSet rs = client.execute(cql.toString(), args.toArray());
        List<Packet> result = new ArrayList<Packet>();
        for (List<Object> row : rs.rows) {
            Packet.Builder b = new Packet.Builder();
            b.index = longVal(row, rs, "packet_index");
            b.timestampMs = longVal(row, rs, "timestamp");
            b.protocol = strVal(row, rs, "protocol");
            b.srcIp = strVal(row, rs, "src_ip");
            b.dstIp = strVal(row, rs, "dst_ip");
            b.srcMac = strVal(row, rs, "src_mac");
            b.dstMac = strVal(row, rs, "dst_mac");
            b.srcPort = intVal(row, rs, "src_port");
            b.dstPort = intVal(row, rs, "dst_port");
            b.httpHost = strVal(row, rs, "http_host");
            b.httpUri = strVal(row, rs, "http_uri");
            result.add(b.build());
        }
        return result;
    }

    @Override
    public Map<String, Long> protocolCounts() throws Exception {
        String ks = config.cassandraKeyspace;
        // Cassandra 3 requires GROUP BY to include the partition key, so we
        // aggregate client-side instead (adequate for a basic UI).
        CassandraClient.ResultSet rs = client.execute(
                "SELECT protocol, count FROM " + ks + ".protocols");
        Map<String, Long> counts = new HashMap<String, Long>();
        for (List<Object> row : rs.rows) {
            Object p = row.get(0);
            Object c = row.get(1);
            String key = p == null ? "UNKNOWN" : p.toString();
            long val = c == null ? 0L : ((Number) c).longValue();
            Long cur = counts.get(key);
            counts.put(key, cur == null ? val : cur + val);
        }
        return counts;
    }

    @Override
    public void close() throws Exception {
        if (client != null) {
            client.close();
        }
    }

    private static int idx(String[] names, String name) {
        for (int i = 0; i < names.length; i++) {
            if (name.equals(names[i])) {
                return i;
            }
        }
        return -1;
    }

    private static String strVal(List<Object> row, CassandraClient.ResultSet rs, String name) {
        int i = idx(rs.columnNames, name);
        if (i < 0 || i >= row.size() || row.get(i) == null) {
            return null;
        }
        return row.get(i).toString();
    }

    private static long longVal(List<Object> row, CassandraClient.ResultSet rs, String name) {
        int i = idx(rs.columnNames, name);
        if (i < 0 || i >= row.size() || row.get(i) == null) {
            return -1;
        }
        return ((Number) row.get(i)).longValue();
    }

    private static int intVal(List<Object> row, CassandraClient.ResultSet rs, String name) {
        int i = idx(rs.columnNames, name);
        if (i < 0 || i >= row.size() || row.get(i) == null) {
            return -1;
        }
        return ((Number) row.get(i)).intValue();
    }
}
