package com.pcap.process;

import com.pcap.config.Config;
import com.pcap.stats.Statistics;
import com.pcap.storage.Storage;

import java.io.File;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Watches the input folder for new PCAP files (Level 1) and submits each
 * discovered file to a bounded thread pool for concurrent processing
 * (Level 2 - multiple files at the same time).
 */
public final class FolderWatcher implements AutoCloseable {

    private final Config config;
    private final StorageFactory storageFactory;
    private final Statistics statistics;

    private final ExecutorService pool;
    private final Set<String> seen = new HashSet<String>();

    private volatile boolean running = true;
    private Thread watcherThread;
    private Thread statsThread;

    public FolderWatcher(Config config, StorageFactory storageFactory, Statistics statistics) {
        this.config = config;
        this.storageFactory = storageFactory;
        this.statistics = statistics;
        this.pool = Executors.newFixedThreadPool(Math.max(1, config.threadsCount));
    }

    public void start() {
        File input = new File(config.inputFolder);
        if (!input.exists() && !input.mkdirs()) {
            throw new IllegalStateException("Cannot create input folder " + input);
        }

        watcherThread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (running) {
                    try {
                        scan();
                    } catch (Exception e) {
                        System.err.println("[watcher] " + e);
                    }
                    try {
                        Thread.sleep(config.watchIntervalMs);
                    } catch (InterruptedException ignore) {
                        if (!running) {
                            break;
                        }
                    }
                }
            }
        }, "folder-watcher");
        watcherThread.setDaemon(true);
        watcherThread.start();

        statsThread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (running) {
                    try {
                        Thread.sleep(config.statsIntervalMs);
                    } catch (InterruptedException ignore) {
                    }
                    System.out.println("[stats] " + statistics.snapshot());
                }
            }
        }, "stats-reporter");
        statsThread.setDaemon(true);
        statsThread.start();
    }

    private void scan() {
        File input = new File(config.inputFolder);
        File[] files = input.listFiles();
        if (files == null) {
            return;
        }
        for (File f : files) {
            if (!f.isFile()) {
                continue;
            }
            String key = f.getAbsolutePath();
            synchronized (seen) {
                if (seen.contains(key)) {
                    continue;
                }
                if (!config.isCaptureFile(f.getName())) {
                    continue;
                }
                seen.add(key);
            }
            Storage storage = storageFactory.create();
            FileProcessor processor = new FileProcessor(f, config, storage, statistics);
            pool.submit(processor);
            System.out.println("[watcher] queued " + f.getName());
        }
    }

    @Override
    public void close() throws Exception {
        running = false;
        watcherThread.interrupt();
        statsThread.interrupt();
        pool.shutdown();
        pool.awaitTermination(30, TimeUnit.SECONDS);
    }
}
