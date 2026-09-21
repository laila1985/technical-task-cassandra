import java.io.*;

/**
 * Generates a small synthetic PCAP file for validating the parser.
 * Produces Ethernet + IPv4 + TCP + HTTP packets and one UDP packet.
 */
public class PcapGen {
    public static void main(String[] args) throws Exception {
        String out = args.length > 0 ? args[0] : "test.pcap";
        DataOutputStream d = new DataOutputStream(new FileOutputStream(out));
        // global header: magic little-endian us, version 2.4, snaplen, ethernet
        writeIntLE(d, 0xA1B2C3D4);
        d.writeShort(swap((short) 2)); d.writeShort(swap((short) 4)); // version
        writeIntLE(d, 0);   // thiszone
        writeIntLE(d, 0);   // sigfigs
        writeIntLE(d, 65535); // snaplen
        writeIntLE(d, 1);   // network: ethernet

        // packet 1: TCP SYN
        byte[] p1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 12345, 80, 0x02, 0, 0, null);
        writePacket(d, 1000000, p1);

        // packet 2: TCP PSH+ACK with HTTP GET payload
        String http = "GET /images/logo.png HTTP/1.1\r\nHost: example.com\r\nContent-Type: image/png\r\n\r\n";
        byte[] p2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 12346, 80, 0x18, 1, 1, http.getBytes("ISO-8859-1"));
        writePacket(d, 1001000, p2);

        // packet 3: UDP
        byte[] p3 = buildUdpPacket("10.0.0.2", "10.0.0.1", 53, 53000, new byte[]{0,1,2,3,4});
        writePacket(d, 1002000, p3);

        // packet 4: TCP PSH+ACK HTTP response with a PNG image body
        String respHead = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 8\r\n\r\n";
        byte[] pngBody = new byte[]{(byte)0x89, 'P','N','G', '\r','\n', 0x1A, '\n'};
        byte[] respPayload = new byte[respHead.length() + pngBody.length];
        System.arraycopy(respHead.getBytes("ISO-8859-1"), 0, respPayload, 0, respHead.length());
        System.arraycopy(pngBody, 0, respPayload, respHead.length(), pngBody.length);
        byte[] p4 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 12346, 0x18, 1, 1, respPayload);
        writePacket(d, 1003000, p4);

        d.close();
        System.out.println("Wrote " + out);
    }

    static byte[] buildTcpPacket(String sip, String dip, int sport, int dport,
                                 int flags, int seq, int ack, byte[] payload) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DataOutputStream o = new DataOutputStream(b);
        // Ethernet header
        byte[] srcMac = new byte[]{0,1,2,3,4,5};
        byte[] dstMac = new byte[]{6,7,8,9,10,11};
        o.write(dstMac); o.write(srcMac);
        o.writeShort(0x0800); // IPv4 (big-endian)
        // IPv4 header
        int totalLen = 20 + 20 + (payload == null ? 0 : payload.length);
        o.writeByte(0x45); // version 4, IHL 5
        o.writeByte(0);    // DSCP/ECN
        o.writeShort(totalLen);
        o.writeShort(0x1234); // id
        o.writeShort(0);   // flags+frag
        o.writeByte(64);   // TTL
        o.writeByte(6);    // TCP
        o.writeShort(0);   // checksum
        writeIp(o, sip); writeIp(o, dip);
        // TCP header
        o.writeShort(sport);
        o.writeShort(dport);
        writeIntBE(o, seq);
        writeIntBE(o, ack);
        o.writeByte(0x50); // data offset 5 (20 bytes)
        o.writeByte(flags);
        o.writeShort(0xFFFF); // window
        o.writeShort(0); // checksum
        o.writeShort(0); // urgent
        if (payload != null) o.write(payload);
        o.close();
        return b.toByteArray();
    }

    static byte[] buildUdpPacket(String sip, String dip, int sport, int dport, byte[] payload) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DataOutputStream o = new DataOutputStream(b);
        byte[] srcMac = new byte[]{0,1,2,3,4,5};
        byte[] dstMac = new byte[]{6,7,8,9,10,11};
        o.write(dstMac); o.write(srcMac);
        o.writeShort(0x0800);
        int totalLen = 20 + 8 + (payload == null ? 0 : payload.length);
        o.writeByte(0x45);
        o.writeByte(0);
        o.writeShort(totalLen);
        o.writeShort(0x5678);
        o.writeShort(0);
        o.writeByte(64);
        o.writeByte(17); // UDP
        o.writeShort(0);
        writeIp(o, sip); writeIp(o, dip);
        o.writeShort(sport);
        o.writeShort(dport);
        o.writeShort(8 + (payload == null ? 0 : payload.length)); // length
        o.writeShort(0); // checksum
        if (payload != null) o.write(payload);
        o.close();
        return b.toByteArray();
    }

    static void writeIp(DataOutputStream o, String ip) throws Exception {
        String[] p = ip.split("\\.");
        for (String s : p) o.writeByte(Integer.parseInt(s));
    }

    static void writeIntBE(DataOutputStream o, int v) throws Exception {
        o.writeInt(v);
    }

    static void writeIntLE(DataOutputStream o, int v) throws Exception {
        o.writeByte(v & 0xFF); o.writeByte((v >> 8) & 0xFF);
        o.writeByte((v >> 16) & 0xFF); o.writeByte((v >> 24) & 0xFF);
    }

    static short swap(short s) {
        return (short) (((s & 0xFF) << 8) | ((s >> 8) & 0xFF));
    }

    static void writePacket(DataOutputStream d, long tsMicros, byte[] data) throws Exception {
        writeIntLE(d, (int) (tsMicros / 1000000)); // ts sec
        writeIntLE(d, (int) (tsMicros % 1000000)); // ts frac (us)
        writeIntLE(d, data.length); // caplen
        writeIntLE(d, data.length); // wirelen
        d.write(data);
    }
}
