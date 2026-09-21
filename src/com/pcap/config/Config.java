package com.pcap.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * Application configuration loaded from a Java properties file.
 * All paths, database parameters and thread limits live here (Level 2).
 */
public final class Config {

    public String inputFolder;
    public String outputFolder;
    public String storageFileFolder;
    public String processedFolder;
    public String failedFolder;
    public long watchIntervalMs;
    public Set<String> extensions;

    public int threadsCount;
    public int dbBatchSize;
    public int parserBufferSize;

    public String storageMode; // cassandra | file | none

    public String cassandraContactPoints;
    public int cassandraPort;
    public String cassandraKeyspace;
    public String cassandraUsername;
    public String cassandraPassword;
    public String cassandraConsistency;
    public int cassandraReplicationFactor;
    public int cassandraConnectRetries;
    public long cassandraConnectRetryDelayMs;

    public long statsIntervalMs;

    public Set<String> imageContentTypes;

    private Config() {
    }

    public static Config load(String path) {
        Properties props = new Properties();
        File file = new File(path);
        InputStream in = null;
        try {
            if (file.exists()) {
                in = new FileInputStream(file);
            } else {
                in = Config.class.getClassLoader().getResourceAsStream("application.properties");
            }
            if (in == null) {
                throw new IllegalStateException("Configuration file not found: " + path);
            }
            props.load(in);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load configuration from " + path, e);
        } finally {
            if (in != null) {
                try { in.close(); } catch (Exception ignore) { }
            }
        }
        return fromProperties(props);
    }

    private static Config fromProperties(Properties p) {
        Config c = new Config();

        c.inputFolder = get(p, "input.folder", "./input");
        c.outputFolder = get(p, "output.folder", "./output/images");
        c.storageFileFolder = get(p, "storage.file.folder", "./output/data");
        c.processedFolder = get(p, "processed.folder", "");
        c.failedFolder = get(p, "failed.folder", "");
        c.watchIntervalMs = getLong(p, "watch.interval.ms", 2000L);
        c.extensions = toSet(get(p, "input.extensions", "pcap,pcapng,cap"));

        c.threadsCount = getInt(p, "threads.count", 4);
        c.dbBatchSize = getInt(p, "db.batch.size", 200);
        c.parserBufferSize = getInt(p, "parser.buffer.size", 1000);

        c.storageMode = get(p, "storage.mode", "cassandra").trim().toLowerCase();

        c.cassandraContactPoints = get(p, "cassandra.contact.points", "127.0.0.1");
        c.cassandraPort = getInt(p, "cassandra.port", 9042);
        c.cassandraKeyspace = get(p, "cassandra.keyspace", "pcap_analysis");
        c.cassandraUsername = get(p, "cassandra.username", "");
        c.cassandraPassword = get(p, "cassandra.password", "");
        c.cassandraConsistency = get(p, "cassandra.consistency", "LOCAL_ONE");
        c.cassandraReplicationFactor = getInt(p, "cassandra.replication.factor", 1);
        c.cassandraConnectRetries = getInt(p, "cassandra.connect.retries", 5);
        c.cassandraConnectRetryDelayMs = getLong(p, "cassandra.connect.retry.delay.ms", 2000L);

        c.statsIntervalMs = getLong(p, "stats.interval.ms", 5000L);

        c.imageContentTypes = toSet(get(p, "image.content.types",
                "image/png,image/jpeg,image/jpg,image/gif,image/bmp,image/webp,image/tiff,image/svg+xml,image/x-icon"));

        return c;
    }

    private static String get(Properties p, String key, String def) {
        // Environment-variable override: dot -> underscore, uppercase.
        // e.g. cassandra.contact.points -> CASSANDRA_CONTACT_POINTS
        String env = System.getenv(key.replace('.', '_').toUpperCase());
        if (env != null && !env.trim().isEmpty()) {
            return env.trim();
        }
        String v = p.getProperty(key);
        return (v == null || v.trim().isEmpty()) ? def : v.trim();
    }

    private static int getInt(Properties p, String key, int def) {
        try {
            return Integer.parseInt(get(p, key, String.valueOf(def)));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static long getLong(Properties p, String key, long def) {
        try {
            return Long.parseLong(get(p, key, String.valueOf(def)));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static Set<String> toSet(String csv) {
        Set<String> s = new HashSet<String>();
        for (String part : csv.split(",")) {
            String t = part.trim().toLowerCase();
            if (!t.isEmpty()) {
                s.add(t);
            }
        }
        return s;
    }

    /** Returns whether the given file extension is a recognized capture file. */
    public boolean isCaptureFile(String fileName) {
        int i = fileName.lastIndexOf('.');
        if (i < 0) {
            return false;
        }
        return extensions.contains(fileName.substring(i + 1).toLowerCase());
    }

    public String toString() {
        return "Config{" +
                "inputFolder=" + inputFolder +
                ", storageMode=" + storageMode +
                ", threads=" + threadsCount +
                ", cassandra=" + cassandraContactPoints + ":" + cassandraPort +
                "/" + cassandraKeyspace +
                ", extensions=" + Arrays.toString(extensions.toArray()) +
                '}';
    }
}
