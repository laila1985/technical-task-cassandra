package com.pcap;

import com.pcap.config.Config;
import com.pcap.process.FolderWatcher;
import com.pcap.process.StorageFactory;
import com.pcap.stats.Statistics;
import com.pcap.storage.Storage;
import com.pcap.ui.SearchUi;

/**
 * Application entry point.
 *
 * Usage:
 *   java com.pcap.Application [--config path] [--ui] [--once file.pcap]
 *
 * Defaults to watching the configured input folder. With --ui it also opens
 * the Swing search window. With --once it processes a single file and exits.
 */
public final class Application {

    public static void main(String[] args) throws Exception {
        String configPath = "conf/application.properties";
        boolean withUi = false;
        String onceFile = null;

        for (int i = 0; i < args.length; i++) {
            if ("--config".equals(args[i]) && i + 1 < args.length) {
                configPath = args[++i];
            } else if ("--ui".equals(args[i])) {
                withUi = true;
            } else if ("--once".equals(args[i]) && i + 1 < args.length) {
                onceFile = args[++i];
            }
        }

        Config config = Config.load(configPath);
        System.out.println("Loaded: " + config);

        Statistics statistics = new Statistics();
        StorageFactory factory = new StorageFactory(config);

        if (onceFile != null) {
            processOnce(onceFile, config, statistics, factory);
            return;
        }

        FolderWatcher watcher = new FolderWatcher(config, factory, statistics);
        watcher.start();

        if (withUi) {
            Storage uiStorage = factory.create();
            uiStorage.init();
            SearchUi ui = new SearchUi(config, uiStorage);
            ui.show();
        }

        System.out.println("PCAP Processor started. Watching " + config.inputFolder
                + " (Ctrl+C to stop).");

        // Keep alive until interrupted.
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    watcher.close();
                } catch (Exception ignore) {
                }
            }
        }));

        Thread.currentThread().join();
    }

    private static void processOnce(String path, Config config,
                                    Statistics statistics, StorageFactory factory) throws Exception {
        Storage storage = factory.create();
        com.pcap.process.FileProcessor processor =
                new com.pcap.process.FileProcessor(new java.io.File(path), config, storage, statistics);
        processor.run();
        System.out.println("[once] " + processor.getStatus()
                + (processor.getError() != null ? " - " + processor.getError() : ""));
        System.out.println("[stats] " + statistics.snapshot());
    }
}
