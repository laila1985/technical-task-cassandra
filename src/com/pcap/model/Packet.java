package com.pcap.model;

/**
 * Immutable representation of a single decoded network packet.
 * Fields may be null when the corresponding protocol layer is absent.
 */
public final class Packet {

    public final long index;         // packet ordinal within the capture
    public final long timestampMs;   // epoch millis
    public final long captureLen;    // captured length (caplen)
    public final long wireLen;       // original length (len)

    // Ethernet
    public final String srcMac;
    public final String dstMac;
    public final String etherType;   // hex string e.g. "0800"

    // IP
    public final String srcIp;
    public final String dstIp;
    public final int ipProtocol;     // IANA protocol number (6 = TCP, 17 = UDP ...)
    public final String ipProtocolName;

    // TCP / UDP
    public final int srcPort;
    public final int dstPort;
    public final String tcpFlags;    // e.g. "PA" or "S"
    public final long seq;
    public final long ack;

    // HTTP (when detected from TCP payload)
    public final String httpHost;
    public final String httpUri;
    public final String httpMethod;
    public final int httpStatus;
    public final String httpContentType;

    public final int payloadSize;
    public final int totalSize;

    public final String protocol;    // highest-level protocol label for stats

    // Raw payload (may be large); kept for image extraction. Nullable to save memory.
    public final byte[] payload;

    private Packet(Builder b) {
        this.index = b.index;
        this.timestampMs = b.timestampMs;
        this.captureLen = b.captureLen;
        this.wireLen = b.wireLen;
        this.srcMac = b.srcMac;
        this.dstMac = b.dstMac;
        this.etherType = b.etherType;
        this.srcIp = b.srcIp;
        this.dstIp = b.dstIp;
        this.ipProtocol = b.ipProtocol;
        this.ipProtocolName = b.ipProtocolName;
        this.srcPort = b.srcPort;
        this.dstPort = b.dstPort;
        this.tcpFlags = b.tcpFlags;
        this.seq = b.seq;
        this.ack = b.ack;
        this.httpHost = b.httpHost;
        this.httpUri = b.httpUri;
        this.httpMethod = b.httpMethod;
        this.httpStatus = b.httpStatus;
        this.httpContentType = b.httpContentType;
        this.payloadSize = b.payloadSize;
        this.totalSize = b.totalSize;
        this.protocol = b.protocol;
        this.payload = b.payload;
    }

    public static class Builder {
        public long index;
        public long timestampMs;
        public long captureLen;
        public long wireLen;
        public String srcMac;
        public String dstMac;
        public String etherType;
        public String srcIp;
        public String dstIp;
        public int ipProtocol = -1;
        public String ipProtocolName;
        public int srcPort = -1;
        public int dstPort = -1;
        public String tcpFlags;
        public long seq = -1;
        public long ack = -1;
        public String httpHost;
        public String httpUri;
        public String httpMethod;
        public int httpStatus = -1;
        public String httpContentType;
        public int payloadSize;
        public int totalSize;
        public String protocol;
        public byte[] payload;

        public Packet build() {
            return new Packet(this);
        }
    }
}
