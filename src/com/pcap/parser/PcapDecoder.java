package com.pcap.parser;

import com.pcap.model.Packet;

/**
 * Decodes a single raw frame into a {@link Packet}.
 * Handles Ethernet / Linux cooked / Raw IP link layers and
 * IPv4 / IPv6 / ARP network layers. Transport decoding lives in
 * {@link TransportDecoder}.
 */
public final class PcapDecoder {

    public static final int LINKTYPE_ETHERNET = 1;
    public static final int LINKTYPE_RAW = 101;
    public static final int LINKTYPE_LOOP = 108;
    public static final int LINKTYPE_LINUX_SLL = 113;
    public static final int LINKTYPE_IEEE802_11 = 105;

    private PcapDecoder() {
    }

    public static Packet decode(byte[] data, long tsMs, long wireLen, long capLen, long index, int linkType) {
        Packet.Builder b = new Packet.Builder();
        b.timestampMs = tsMs;
        b.wireLen = wireLen;
        b.captureLen = capLen;
        b.index = index;
        b.totalSize = data.length;
        b.protocol = "ETHERNET";

        int off;

        switch (linkType) {
            case LINKTYPE_ETHERNET:
                if (data.length < 14) {
                    return b.build();
                }
                b.srcMac = mac(data, 6);
                b.dstMac = mac(data, 0);
                int etherType = PcapParser.u16be(data, 12);
                b.etherType = hex2(etherType);
                off = 14;
                if (etherType == 0x0800) {
                    decodeIpv4(data, off, b);
                } else if (etherType == 0x86DD) {
                    decodeIpv6(data, off, b);
                } else if (etherType == 0x0806) {
                    decodeArp(data, off, b);
                } else if (etherType == 0x8100 && data.length >= 18) {
                    int innerType = PcapParser.u16be(data, 16);
                    b.etherType = hex2(innerType);
                    off = 18;
                    if (innerType == 0x0800) {
                        decodeIpv4(data, off, b);
                    } else if (innerType == 0x86DD) {
                        decodeIpv6(data, off, b);
                    }
                }
                break;
            case LINKTYPE_RAW:
            case LINKTYPE_LOOP:
                if (data.length >= 1) {
                    int v = data[0] & 0xF0;
                    if (v == 0x40) {
                        decodeIpv4(data, 0, b);
                    } else if (v == 0x60) {
                        decodeIpv6(data, 0, b);
                    }
                }
                break;
            case LINKTYPE_LINUX_SLL:
                if (data.length >= 16) {
                    int proto = PcapParser.u16be(data, 14);
                    b.etherType = hex2(proto);
                    off = 16;
                    if (proto == 0x0800) {
                        decodeIpv4(data, off, b);
                    } else if (proto == 0x86DD) {
                        decodeIpv6(data, off, b);
                    }
                }
                break;
            case LINKTYPE_IEEE802_11:
                b.protocol = "80211";
                break;
            default:
                break;
        }
        return b.build();
    }
    private static void decodeArp(byte[] data, int off, Packet.Builder b) {
        b.protocol = "ARP";
        if (data.length < off + 28) {
            return;
        }
        b.srcIp = ipv4(data, off + 14);
        b.dstIp = ipv4(data, off + 24);
    }

    private static void decodeIpv4(byte[] data, int off, Packet.Builder b) {
        if (data.length < off + 20) {
            return;
        }
        int ihl = (data[off] & 0x0F) * 4;
        if (ihl < 20 || data.length < off + ihl) {
            return;
        }
        int totalLen = PcapParser.u16be(data, off + 2);
        int proto = data[off + 9] & 0xFF;
        b.srcIp = ipv4(data, off + 12);
        b.dstIp = ipv4(data, off + 16);
        b.ipProtocol = proto;
        b.ipProtocolName = ipProtocolName(proto);

        int payloadOff = off + ihl;
        int ipPayloadLen = Math.max(0, Math.min(totalLen - ihl, data.length - payloadOff));

        if (proto == 6) {
            TransportDecoder.decodeTcp(data, payloadOff, ipPayloadLen, b);
        } else if (proto == 17) {
            TransportDecoder.decodeUdp(data, payloadOff, ipPayloadLen, b);
        } else if (proto == 1) {
            b.protocol = "ICMP";
        } else if (b.protocol.equals("ETHERNET")) {
            b.protocol = "IP";
        }
        if (b.payloadSize == 0) {
            b.payloadSize = ipPayloadLen;
        }
    }

    private static void decodeIpv6(byte[] data, int off, Packet.Builder b) {
        if (data.length < off + 40) {
            return;
        }
        int payloadLen = PcapParser.u16be(data, off + 4);
        int proto = data[off + 6] & 0xFF;
        b.srcIp = ipv6(data, off + 8);
        b.dstIp = ipv6(data, off + 24);
        b.ipProtocol = proto;
        b.ipProtocolName = ipProtocolName(proto);

        int payloadOff = off + 40;
        int ipPayloadLen = Math.max(0, Math.min(payloadLen, data.length - payloadOff));
        if (proto == 6) {
            TransportDecoder.decodeTcp(data, payloadOff, ipPayloadLen, b);
        } else if (proto == 17) {
            TransportDecoder.decodeUdp(data, payloadOff, ipPayloadLen, b);
        } else if (proto == 58) {
            b.protocol = "ICMP6";
        } else if (b.protocol.equals("ETHERNET")) {
            b.protocol = "IPV6";
        }
        if (b.payloadSize == 0) {
            b.payloadSize = ipPayloadLen;
        }
    }

    static String mac(byte[] d, int o) {
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                d[o] & 0xFF, d[o + 1] & 0xFF, d[o + 2] & 0xFF, d[o + 3] & 0xFF, d[o + 4] & 0xFF, d[o + 5] & 0xFF);
    }

    static String ipv4(byte[] d, int o) {
        return (d[o] & 0xFF) + "." + (d[o + 1] & 0xFF) + "." + (d[o + 2] & 0xFF) + "." + (d[o + 3] & 0xFF);
    }

    static String ipv6(byte[] d, int o) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(String.format("%x", PcapParser.u16be(d, o + i)));
        }
        return sb.toString();
    }

    static String hex2(int v) {
        return String.format("%04X", v & 0xFFFF);
    }

    static String ipProtocolName(int proto) {
        switch (proto) {
            case 1: return "ICMP";
            case 6: return "TCP";
            case 17: return "UDP";
            case 58: return "ICMPv6";
            case 2: return "IGMP";
            default: return String.valueOf(proto);
        }
    }
}

