package com.pcap.storage;

import com.pcap.model.Aggregations;
import com.pcap.model.CaptureSummary;
import com.pcap.model.ImageRecord;
import com.pcap.model.Packet;

import java.util.List;
import java.util.Map;

/**
 * Abstraction over the storage backend so the same pipeline can target
 * Cassandra (Level 3), local files, or no persistence at all.
 */
public interface Storage {

    /** Called once at startup to initialise connections / folders. */
    void init() throws Exception;

    /** Persists a single packet belonging to the given capture file. */
    void storePacket(String fileId, Packet packet) throws Exception;

    /** Flushes any pending buffered packets. */
    void flush() throws Exception;

    /** Persists per-capture aggregation data. */
    void storeCapture(CaptureSummary summary) throws Exception;

    /** Persists per-capture protocol / ip-pair / endpoint aggregations. */
    void storeAggregations(String fileId, Aggregations agg) throws Exception;

    /** Persists an extracted image record. */
    void storeImage(ImageRecord image) throws Exception;

    /** Search packets by optional protocol and/or IP (Level 4 UI). */
    List<Packet> search(String protocol, String ip, int limit) throws Exception;

    /** Returns aggregated protocol counts across captures (for stats/UI). */
    Map<String, Long> protocolCounts() throws Exception;

    /** Releases resources. */
    void close() throws Exception;
}

