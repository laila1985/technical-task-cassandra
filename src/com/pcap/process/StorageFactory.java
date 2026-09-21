package com.pcap.process;

import com.pcap.config.Config;
import com.pcap.storage.CassandraStorage;
import com.pcap.storage.FileStorage;
import com.pcap.storage.NoopStorage;
import com.pcap.storage.Storage;

/**
 * Creates a fresh Storage instance for each processed file so that
 * concurrent file processors never share mutable connection state.
 */
public final class StorageFactory {

    private final Config config;

    public StorageFactory(Config config) {
        this.config = config;
    }

    public Storage create() {
        String mode = config.storageMode;
        if ("cassandra".equals(mode)) {
            return new CassandraStorage(config);
        } else if ("file".equals(mode)) {
            return new FileStorage(config);
        } else {
            return new NoopStorage();
        }
    }
}
