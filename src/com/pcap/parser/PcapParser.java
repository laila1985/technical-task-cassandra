package com.pcap.parser;

import com.pcap.model.Packet;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Streaming parser for PCAP and PCAP-NG capture files.
 * Reads the global header, then iterates packet records, delegating the
 * actual protocol decoding to {@link PcapDecoder}.
 */
public final class PcapParser {

    public interface PacketHandler {
        boolean onPacket(Packet packet) throws Exception;
    }

    private static final int MAGIC_US = 0xA1B2C3D4;
    private static final int MAGIC_US_BE = 0xD4C3B2A1;
    private static final int MAGIC_NS = 0xA1B23C4D;
    private static final int MAGIC_NS_BE = 0x4D3CB2A1;

    private final InputStream in;
    private boolean bigEndian;
    private boolean nanoResolution;
    private int linkType;

    public PcapParser(InputStream in) {
        this.in = in;
    }

    public int readGlobalHeader() throws IOException {
        byte[] magic = new byte[4];
        readFully(magic, 0, 4);
        int mLe = (int) u32le(magic, 0);

        if (mLe == MAGIC_US || mLe == MAGIC_US_BE || mLe == MAGIC_NS || mLe == MAGIC_NS_BE) {
            bigEndian = (mLe == MAGIC_US_BE || mLe == MAGIC_NS_BE);
            nanoResolution = (mLe == MAGIC_NS || mLe == MAGIC_NS_BE);
            byte[] h = new byte[20];
            readFully(h, 0, 20);
            linkType = bigEndian ? (int) u32be(h, 16) : (int) u32le(h, 16);
            return linkType;
        }

        if (mLe == 0x0A0D0D0A) { // PCAP-NG section header
            readPcapngSection();
            return linkType;
        }
        throw new IOException("Unsupported file format (magic=0x" + Integer.toHexString(mLe) + ")");
    }

    private void readPcapngSection() throws IOException {
        byte[] h = new byte[8];
        readFully(h, 0, 8);
        int blockLen = (int) u32le(h, 4);
        byte[] rest = new byte[Math.max(0, blockLen - 8)];
        readFully(rest, 0, rest.length);
        if (rest.length >= 4) {
            int bom = (int) u32be(rest, 0);
            bigEndian = (bom == 0x1A2B3C4D);
        }
        linkType = 1; // default Ethernet
        scanForLinkType();
    }

    private void scanForLinkType() throws IOException {
        byte[] hdr = new byte[8];
        while (true) {
            readFully(hdr, 0, 8);
            int type = (int) u32le(hdr, 0);
            int len = (int) u32le(hdr, 4);
            if (len < 12 || len > 1024 * 1024) {
                throw new IOException("Invalid PCAP-NG block length: " + len);
            }
            byte[] body = new byte[len - 12];
            readFully(body, 0, body.length);
            byte[] tail = new byte[4];
            readFully(tail, 0, 4);
            if (type == 0x00000001 && body.length >= 8) { // IDB
                linkType = bigEndian ? u16be(body, 0) : u16le(body, 0);
                return;
            }
        }
    }

    public long parse(PacketHandler handler) throws Exception {
        long count = 0;
        while (true) {
            Packet p = readNextPacket(count);
            if (p == null) {
                break;
            }
            count++;
            if (!handler.onPacket(p)) {
                break;
            }
        }
        return count;
    }

    private Packet readNextPacket(long index) throws IOException {
        byte[] h = new byte[16];
        int n = readSome(h, 0, 16);
        if (n == 0) {
            return null;
        }
        if (n < 16) {
            throw new EOFException("Truncated packet header");
        }
        long tsSec, tsFrac;
        int caplen, wirelen;
        if (bigEndian) {
            tsSec = u32be(h, 0);
            tsFrac = u32be(h, 4);
            caplen = (int) u32be(h, 8);
            wirelen = (int) u32be(h, 12);
        } else {
            tsSec = u32le(h, 0);
            tsFrac = u32le(h, 4);
            caplen = (int) u32le(h, 8);
            wirelen = (int) u32le(h, 12);
        }
        long fracMs = nanoResolution ? tsFrac / 1_000_000L : tsFrac / 1_000L;
        long timestampMs = tsSec * 1000L + fracMs;

        if (caplen < 0 || caplen > 64 * 1024 * 1024) {
            throw new IOException("Invalid capture length: " + caplen);
        }
        byte[] data = new byte[caplen];
        readFully(data, 0, caplen);

        return PcapDecoder.decode(data, timestampMs, wirelen, caplen, index, linkType);
    }

    private int readSome(byte[] b, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int r = in.read(b, off + total, len - total);
            if (r < 0) {
                break;
            }
            total += r;
        }
        return total;
    }

    private void readFully(byte[] b, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int r = in.read(b, off + total, len - total);
            if (r < 0) {
                throw new EOFException("Unexpected end of stream");
            }
            total += r;
        }
    }

    static int u16le(byte[] b, int o) { return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8); }
    static int u16be(byte[] b, int o) { return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF); }
    static long u32le(byte[] b, int o) {
        return (b[o] & 0xFFL) | ((b[o + 1] & 0xFFL) << 8) | ((b[o + 2] & 0xFFL) << 16) | ((b[o + 3] & 0xFFL) << 24);
    }
    static long u32be(byte[] b, int o) {
        return ((b[o] & 0xFFL) << 24) | ((b[o + 1] & 0xFFL) << 16) | ((b[o + 2] & 0xFFL) << 8) | (b[o + 3] & 0xFFL);
    }
}
