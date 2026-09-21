package com.pcap.cassandra;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

/**
 * Encoders/decoders for CQL v4 native protocol value types.
 * Only the subset of types used by this application is implemented.
 */
public final class TypeCodec {

    private TypeCodec() {
    }

    // --- primitive type ids (CQL native protocol v4) ---
    public static final int CUSTOM = 0x0000;
    public static final int ASCII = 0x0001;
    public static final int BIGINT = 0x0002;
    public static final int BLOB = 0x0003;
    public static final int BOOLEAN = 0x0004;
    public static final int INT = 0x0009;
    public static final int TEXT = 0x000A;
    public static final int TIMESTAMP = 0x000B;
    public static final int UUID = 0x000C;
    public static final int VARCHAR = 0x000D;

    // --- collection type ids (used when parsing result-set metadata) ---
    public static final int LIST = 0x0020;
    public static final int SET = 0x0021;
    public static final int MAP = 0x0022;

    public static void writeString(java.io.DataOutputStream out, String s) throws Exception {
        byte[] b = s == null ? null : s.getBytes(StandardCharsets.UTF_8);
        if (b == null) {
            out.writeShort(-1);
        } else {
            out.writeShort(b.length);
            out.write(b);
        }
    }

    public static void writeLongString(java.io.DataOutputStream out, String s) throws Exception {
        byte[] b = s == null ? null : s.getBytes(StandardCharsets.UTF_8);
        if (b == null) {
            out.writeInt(-1);
        } else {
            out.writeInt(b.length);
            out.write(b);
        }
    }

    /** Writes a CQL "bytes" value (int length + bytes; -1 = null). */
    public static void writeBytes(java.io.DataOutputStream out, byte[] value) throws Exception {
        if (value == null) {
            out.writeInt(-1);
        } else {
            out.writeInt(value.length);
            out.write(value);
        }
    }

    public static void writeInt(java.io.DataOutputStream out, int v) throws Exception {
        out.writeInt(v);
    }

    public static void writeLong(java.io.DataOutputStream out, long v) throws Exception {
        out.writeLong(v);
    }

    public static void writeTimestamp(java.io.DataOutputStream out, long millis) throws Exception {
        out.writeLong(millis);
    }

    public static void writeUuid(java.io.DataOutputStream out, UUID uuid) throws Exception {
        out.writeLong(uuid.getMostSignificantBits());
        out.writeLong(uuid.getLeastSignificantBits());
    }

    public static void writeShort(java.io.DataOutputStream out, int v) throws Exception {
        out.writeShort(v);
    }

    /** Encodes a value by its Java type into the CQL wire format. */
    public static void writeValue(java.io.DataOutputStream out, Object value) throws Exception {
        if (value == null) {
            out.writeInt(-1);
            return;
        }
        if (value instanceof String) {
            byte[] b = ((String) value).getBytes(StandardCharsets.UTF_8);
            out.writeInt(b.length);
            out.write(b);
        } else if (value instanceof Integer) {
            out.writeInt(4);
            out.writeInt((Integer) value);
        } else if (value instanceof Long) {
            out.writeInt(8);
            out.writeLong((Long) value);
        } else if (value instanceof UUID) {
            out.writeInt(16);
            UUID u = (UUID) value;
            out.writeLong(u.getMostSignificantBits());
            out.writeLong(u.getLeastSignificantBits());
        } else if (value instanceof byte[]) {
            byte[] b = (byte[]) value;
            out.writeInt(b.length);
            out.write(b);
        } else if (value instanceof Boolean) {
            out.writeInt(1);
            out.writeByte(((Boolean) value) ? 1 : 0);
        } else {
            throw new IllegalArgumentException("Unsupported value type: " + value.getClass());
        }
    }

    /** Reads a CQL value (int length + bytes) and decodes by type id. */
    public static Object readValue(java.io.DataInputStream in, int typeId) throws Exception {
        int len = in.readInt();
        if (len < 0) {
            return null;
        }
        byte[] b = new byte[len];
        in.readFully(b);
        switch (typeId) {
            case ASCII:
            case TEXT:
            case VARCHAR:
                return new String(b, StandardCharsets.UTF_8);
            case BIGINT:
                return toLong(b);
            case INT:
                return toInt(b);
            case TIMESTAMP:
                return toLong(b);
            case BLOB:
                return b;
            case BOOLEAN:
                return b.length > 0 && b[0] != 0;
            case UUID:
                java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(b);
                return new UUID(bb.getLong(), bb.getLong());
            default:
                return b;
        }
    }

    private static long toLong(byte[] b) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (b[i] & 0xFFL);
        }
        return v;
    }

    private static int toInt(byte[] b) {
        int v = 0;
        for (int i = 0; i < 4; i++) {
            v = (v << 8) | (b[i] & 0xFF);
        }
        return v;
    }

    public static String typeName(int typeId) {
        switch (typeId) {
            case ASCII: return "ascii";
            case BIGINT: return "bigint";
            case BLOB: return "blob";
            case BOOLEAN: return "boolean";
            case INT: return "int";
            case TEXT: return "text";
            case TIMESTAMP: return "timestamp";
            case UUID: return "uuid";
            case VARCHAR: return "varchar";
            default: return "type" + typeId;
        }
    }
}
