package com.pcap.model;

/**
 * Aggregation data accumulated while parsing a single capture file.
 * Passed to the storage backend for persistence (Level 3 aggregation).
 */
public final class Aggregations {

    public final java.util.Map<String, Long> protocolCounts = new java.util.HashMap<String, Long>();
    public final java.util.Map<String, long[]> ipPairs = new java.util.HashMap<String, long[]>();
    public final java.util.Map<String, long[]> endpoints = new java.util.HashMap<String, long[]>();

    // key for ipPairs: "src->dst" ; value: [packets, bytes]
    public void addIpPair(String src, String dst, long bytes) {
        if (src == null || dst == null) {
            return;
        }
        String key = src + "->" + dst;
        long[] v = ipPairs.get(key);
        if (v == null) {
            v = new long[2];
            ipPairs.put(key, v);
        }
        v[0]++;
        v[1] += bytes;
    }

    // key for endpoints: ip ; value: [packetsIn, packetsOut, bytesIn, bytesOut]
    public void addEndpoint(String ip, String mac, boolean outbound, long bytes) {
        if (ip == null) {
            return;
        }
        long[] v = endpoints.get(ip);
        if (v == null) {
            v = new long[4];
            endpoints.put(ip, v);
        }
        if (outbound) {
            v[1]++;
            v[3] += bytes;
        } else {
            v[0]++;
            v[2] += bytes;
        }
    }

    public void addProtocol(String protocol) {
        if (protocol == null) {
            protocol = "UNKNOWN";
        }
        Long c = protocolCounts.get(protocol);
        protocolCounts.put(protocol, c == null ? 1L : c + 1L);
    }
}
