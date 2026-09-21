package com.pcap.model;

/**
 * An extracted image (Level 5) linked back to a capture and packet.
 */
public final class ImageRecord {
    public String fileId;
    public String imageId;
    public String srcIp;
    public String dstIp;
    public String url;
    public String contentLength;
    public String contentType;
    public long size;
    public String filePath;
    public long extractedAt;
}
