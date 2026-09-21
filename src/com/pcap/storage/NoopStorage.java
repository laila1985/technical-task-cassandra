package com.pcap.storage;

import com.pcap.model.Aggregations;
import com.pcap.model.CaptureSummary;
import com.pcap.model.ImageRecord;
import com.pcap.model.Packet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * No-op storage used when storage.mode=none (parse only, statistics only).
 */
public class NoopStorage implements Storage {
    @Override public void init() { }
    @Override public void storePacket(String fileId, Packet p) { }
    @Override public void flush() { }
    @Override public void storeCapture(CaptureSummary s) { }
    @Override public void storeAggregations(String fileId, Aggregations agg) { }
    @Override public void storeImage(ImageRecord img) { }
    @Override public List<Packet> search(String protocol, String ip, int limit) { return new ArrayList<Packet>(); }
    @Override public Map<String, Long> protocolCounts() { return new HashMap<String, Long>(); }
    @Override public void close() { }
}
