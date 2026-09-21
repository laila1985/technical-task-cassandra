package com.pcap.parser;

import com.pcap.model.Packet;

import java.nio.charset.StandardCharsets;

/**
 * Decodes TCP and UDP transport headers and extracts HTTP metadata
 * from payload bytes.
 */
public final class TransportDecoder {

    private TransportDecoder() {
    }

    public static void decodeTcp(byte[] data, int off, int len, Packet.Builder b) {
        if (len < 20) {
            b.protocol = "TCP";
            return;
        }
        b.srcPort = PcapParser.u16be(data, off);
        b.dstPort = PcapParser.u16be(data, off + 2);
        b.seq = PcapParser.u32be(data, off + 4);
        b.ack = PcapParser.u32be(data, off + 8);
        int dataOffset = ((data[off + 12] & 0xF0) >> 4) * 4;
        int flags = data[off + 13] & 0xFF;
        b.tcpFlags = tcpFlags(flags);
        b.protocol = "TCP";

        int hdrLen = Math.max(20, dataOffset);
        int payloadLen = Math.max(0, len - hdrLen);
        if (payloadLen > 0 && off + hdrLen + payloadLen <= data.length) {
            byte[] payload = new byte[payloadLen];
            System.arraycopy(data, off + hdrLen, payload, 0, payloadLen);
            b.payload = payload;
            b.payloadSize = payloadLen;

            if (isHttpPort(b)) {
                decodeHttp(payload, b, isRequestSide(b));
            } else {
                maybeDecodeHttp(payload, b);
            }
        }
    }

    public static void decodeUdp(byte[] data, int off, int len, Packet.Builder b) {
        if (len < 8) {
            b.protocol = "UDP";
            return;
        }
        b.srcPort = PcapParser.u16be(data, off);
        b.dstPort = PcapParser.u16be(data, off + 2);
        int payloadLen = Math.max(0, len - 8);
        int payloadOff = off + 8;
        if (payloadLen > 0 && payloadOff + payloadLen <= data.length) {
            byte[] payload = new byte[payloadLen];
            System.arraycopy(data, payloadOff, payload, 0, payloadLen);
            b.payload = payload;
            b.payloadSize = payloadLen;
        }
        b.protocol = "UDP";
        if (b.dstPort == 53 || b.srcPort == 53) {
            b.protocol = "DNS";
        }
    }

    private static boolean isHttpPort(Packet.Builder b) {
        int sp = b.srcPort;
        int dp = b.dstPort;
        return sp == 80 || dp == 80 || sp == 8080 || dp == 8080
                || sp == 8000 || dp == 8000 || sp == 443 || dp == 443;
    }

    private static boolean isRequestSide(Packet.Builder b) {
        int dp = b.dstPort;
        return dp == 80 || dp == 8080 || dp == 8000 || dp == 443;
    }

    private static void decodeHttp(byte[] payload, Packet.Builder b, boolean requestSide) {
        int headerEnd = findHeaderEnd(payload);
        if (headerEnd < 0) {
            return;
        }
        String head = new String(payload, 0, headerEnd, StandardCharsets.ISO_8859_1);
        if (requestSide) {
            int sp1 = head.indexOf(' ');
            if (sp1 > 0) {
                b.httpMethod = head.substring(0, sp1);
                int sp2 = head.indexOf(' ', sp1 + 1);
                if (sp2 > 0) {
                    b.httpUri = head.substring(sp1 + 1, sp2);
                }
            }
            b.httpHost = headerValue(payload, "Host");
            String ct = headerValue(payload, "Content-Type");
            if (ct != null) {
                b.httpContentType = ct;
            }
            b.protocol = "HTTP";
        } else {
            int sp = head.indexOf(' ');
            if (sp > 0) {
                int sp2 = head.indexOf(' ', sp + 1);
                if (sp2 > 0) {
                    try {
                        b.httpStatus = Integer.parseInt(head.substring(sp + 1, sp2).trim());
                    } catch (NumberFormatException ignore) {
                    }
                }
            }
            String ct = headerValue(payload, "Content-Type");
            if (ct != null) {
                b.httpContentType = ct;
            }
            b.protocol = "HTTP";
        }
    }

    private static int findHeaderEnd(byte[] payload) {
        for (int i = 0; i + 3 < payload.length; i++) {
            if (payload[i] == '\r' && payload[i + 1] == '\n'
                    && payload[i + 2] == '\r' && payload[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static void maybeDecodeHttp(byte[] payload, Packet.Builder b) {
        String head = asciiHead(payload, 16);
        if (head == null) {
            return;
        }
        if (head.startsWith("GET ") || head.startsWith("POST ") || head.startsWith("PUT ")
                || head.startsWith("DELETE ") || head.startsWith("HEAD ") || head.startsWith("OPTIONS ")
                || head.startsWith("HTTP/")) {
            decodeHttp(payload, b, !head.startsWith("HTTP/"));
        }
    }

    private static String headerValue(byte[] payload, String name) {
        String text = new String(payload, StandardCharsets.ISO_8859_1);
        int idx = text.indexOf("\r\n\r\n");
        if (idx < 0) {
            return null;
        }
        String headers = text.substring(0, idx);
        String target = name.toLowerCase() + ":";
        int pos = headers.toLowerCase().indexOf(target);
        if (pos < 0) {
            return null;
        }
        int end = headers.indexOf("\r\n", pos);
        String line = end < 0 ? headers.substring(pos) : headers.substring(pos, end);
        int colon = line.indexOf(':');
        return line.substring(colon + 1).trim();
    }

    private static String asciiHead(byte[] payload, int max) {
        int n = Math.min(max, payload.length);
        for (int i = 0; i < n; i++) {
            int c = payload[i] & 0xFF;
            // Allow tab, CR, LF and printable ASCII (HTTP headers contain CRLF).
            if (c != 0x09 && c != 0x0A && c != 0x0D && (c < 0x20 || c > 0x7E)) {
                return null;
            }
        }
        return new String(payload, 0, n, StandardCharsets.ISO_8859_1);
    }

    private static String tcpFlags(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x01) != 0) sb.append('F');
        if ((flags & 0x02) != 0) sb.append('S');
        if ((flags & 0x04) != 0) sb.append('R');
        if ((flags & 0x08) != 0) sb.append('P');
        if ((flags & 0x10) != 0) sb.append('A');
        if ((flags & 0x20) != 0) sb.append('U');
        return sb.toString();
    }
}
