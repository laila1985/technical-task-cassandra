package com.pcap.cassandra;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal Cassandra CQL native protocol (v4) client implemented from scratch.
 * No external driver is used (project constraint: no Maven/Gradle).
 *
 * Supported: STARTUP, OPTIONS, QUERY (with bound values), RESULT
 * (Void / Rows / SetKeyspace / SchemaChange / Prepared), ERROR.
 */
public final class   implements AutoCloseable {

    // ------------------------------------------------------------------
    // Numbers defined by the Cassandra CQL native protocol (v4).
    // These are just byte values that Cassandra expects on the wire.
    // They are written in hex only because the official spec lists them
    // that way; "0x07" and "7" are the exact same number to Java.
    // ------------------------------------------------------------------

    /** Protocol version we speak (v4). */
    private static final int PROTOCOL_VERSION = 0x04;

    // ---- Consistency levels (the "how many nodes must agree" setting) ----
    public static final int CONSISTENCY_ONE = 0x0001;
    public static final int CONSISTENCY_QUORUM = 0x0004;
    public static final int CONSISTENCY_ALL = 0x0005;
    public static final int CONSISTENCY_LOCAL_QUORUM = 0x0006;
    public static final int CONSISTENCY_LOCAL_ONE = 0x000A;

    // ---- Message types (opcodes): what kind of message a frame carries ----
    private static final int OPCODE_ERROR = 0x00;
    private static final int OPCODE_STARTUP = 0x01;
    private static final int OPCODE_READY = 0x02;
    private static final int OPCODE_AUTHENTICATE = 0x03;
    private static final int OPCODE_QUERY = 0x07;
    private static final int OPCODE_RESULT = 0x08;
    private static final int OPCODE_AUTH_RESPONSE = 0x0F;

    // ---- RESULT message sub-kinds: what a query returned ----
    private static final int RESULT_VOID = 0x0001;
    private static final int RESULT_ROWS = 0x0002;
    private static final int RESULT_SET_KEYSPACE = 0x0003;
    private static final int RESULT_PREPARED = 0x0004;
    private static final int RESULT_SCHEMA_CHANGE = 0x0005;

    // ---- Bit flags in a ROWS result (bits of a single "flags" int) ----
    private static final int ROWS_FLAG_GLOBAL_TABLE_SPEC = 0x0001;
    private static final int ROWS_FLAG_HAS_MORE_PAGES = 0x0002;
    private static final int ROWS_FLAG_NO_METADATA = 0x0004;

    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private int defaultConsistency = CONSISTENCY_LOCAL_ONE;

    private final String host;
    private final int port;
    private final String username;
    private final String password;

    public CassandraClient(String host, int port, String username, String password) {
        this.host = host;
        this.port = port;
        this.username = username;
        this.password = password;
    }

    public void setConsistency(String c) {
        if (c == null) {
            return;
        }
        String s = c.trim().toUpperCase();
        if (s.equals("ONE")) defaultConsistency = CONSISTENCY_ONE;
        else if (s.equals("QUORUM")) defaultConsistency = CONSISTENCY_QUORUM;
        else if (s.equals("ALL")) defaultConsistency = CONSISTENCY_ALL;
        else if (s.equals("LOCAL_QUORUM")) defaultConsistency = CONSISTENCY_LOCAL_QUORUM;
        else defaultConsistency = CONSISTENCY_LOCAL_ONE;
    }

    public void connect() throws Exception {
        socket = new Socket(host, port);
        socket.setTcpNoDelay(true);
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());

        // The handshake: send a STARTUP message telling Cassandra which CQL
        // version we speak. It answers READY (success) or AUTHENTICATE.
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(body);
        d.writeShort(1);                              // one option below
        TypeCodec.writeString(d, "CQL_VERSION");      // option name
        TypeCodec.writeString(d, "3.0.0");           // option value
        sendFrame(OPCODE_STARTUP, body.toByteArray());

        int opcode = readFrame();
        if (opcode == OPCODE_AUTHENTICATE) {
            // Server wants credentials: send username/password (SASL PLAIN:
            // a 0 byte, then username, 0 byte, then password).
            if (username == null || username.isEmpty()) {
                throw new IllegalStateException("Cassandra requires authentication but no username configured");
            }
            ByteArrayOutputStream auth = new ByteArrayOutputStream();
            auth.write(0);
            auth.write(username.getBytes(StandardCharsets.UTF_8));
            auth.write(0);
            auth.write(password.getBytes(StandardCharsets.UTF_8));
            sendFrame(OPCODE_AUTH_RESPONSE, auth.toByteArray());
            opcode = readFrame();
        }
        if (opcode != OPCODE_READY) {
            throw new IllegalStateException("Unexpected startup response opcode 0x" + Integer.toHexString(opcode));
        }
    }

    public ResultSet execute(String cql, Object... values) throws Exception {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(body);

        // 1. The CQL query text itself (4-byte length + bytes).
        TypeCodec.writeLongString(d, cql);

        // 2. The consistency level to use for this query.
        d.writeShort(defaultConsistency);

        // 3. Query parameters. The first byte is a flags bitmask; bit 0 means
        //    "bound values are present". If we have none, just send 0.
        if (values != null && values.length > 0) {
            d.writeByte(0x01); // flag: values present
            d.writeShort(values.length);
            for (Object v : values) {
                TypeCodec.writeValue(d, v);
            }
        } else {
            d.writeByte(0x00); // flag: no values
        }
        sendFrame(OPCODE_QUERY, body.toByteArray());
        return readResult();
    }

    public void executeSimple(String cql) throws Exception {
        execute(cql);
    }

    private void sendFrame(int opcode, byte[] body) throws Exception {
        // Every CQL message starts with a 9-byte header:
        //   version (1) | flags (1) | stream id (2) | opcode (1) | length (4)
        out.writeByte(PROTOCOL_VERSION);
        out.writeByte(0x00);     // flags: none (no compression/tracing)
        out.writeShort(0);       // stream id: 0 (we send requests one at a time)
        out.writeByte(opcode);   // what kind of message this is
        out.writeInt(body.length);
        out.write(body);
        out.flush();
    }

    private int readFrame() throws Exception {
        int version = in.readUnsignedByte();
        int flags = in.readUnsignedByte();
        int stream = in.readUnsignedShort();
        int opcode = in.readUnsignedByte();
        int length = in.readInt();
        if (opcode == OPCODE_ERROR) {
            readError(length);
        }
        consumeBody(length);
        return opcode;
    }

    private void consumeBody(int length) throws Exception {
        long remaining = length;
        while (remaining > 0) {
            long skipped = in.skip(remaining);
            if (skipped <= 0) {
                in.readByte();
                remaining--;
            } else {
                remaining -= skipped;
            }
        }
    }

    private void readError(int length) throws Exception {
        int code = in.readInt();
        int msgLen = in.readUnsignedShort();
        byte[] msg = new byte[msgLen];
        in.readFully(msg);
        consumeBody(length - 4 - 2 - msgLen);
        throw new CassandraException(code, new String(msg, StandardCharsets.UTF_8));
    }

    private ResultSet readResult() throws Exception {
        int version = in.readUnsignedByte();
        int flags = in.readUnsignedByte();
        int stream = in.readUnsignedShort();
        int opcode = in.readUnsignedByte();
        int length = in.readInt();
        if (opcode == OPCODE_ERROR) {
            readError(length);
        }
        if (opcode != OPCODE_RESULT) {
            throw new IllegalStateException("Expected RESULT but got opcode 0x" + Integer.toHexString(opcode));
        }
        // Read the whole result body into memory and parse from it so the
        // socket stream stays aligned regardless of result kind.
        byte[] body = new byte[length];
        in.readFully(body);
        DataInputStream bin = new DataInputStream(new java.io.ByteArrayInputStream(body));
        return parseResult(bin);
    }

    private ResultSet parseResult(DataInputStream in) throws Exception {
        int kind = in.readInt();
        switch (kind) {
            case RESULT_VOID:
                return new ResultSet();
            case RESULT_ROWS:
                return parseRows(in);
            case RESULT_SET_KEYSPACE:
                return new ResultSet();
            case RESULT_PREPARED:
                return parsePrepared(in);
            case RESULT_SCHEMA_CHANGE:
                return new ResultSet();
            default:
                return new ResultSet();
        }
    }

    private ResultSet parseRows(DataInputStream in) throws Exception {
        int flags = in.readInt();
        int columnCount = in.readInt();

        // The flags int is a bitmask. Check the bits we care about.
        boolean hasGlobalSpec = (flags & ROWS_FLAG_GLOBAL_TABLE_SPEC) != 0;
        boolean hasMorePages = (flags & ROWS_FLAG_HAS_MORE_PAGES) != 0;
        boolean noMetadata = (flags & ROWS_FLAG_NO_METADATA) != 0;

        if (hasMorePages) {
            // A paging state blob follows; we don't page, so skip it.
            int psLen = in.readInt();
            byte[] ps = new byte[psLen];
            in.readFully(ps);
        }

        String[] names = new String[columnCount];
        int[] types = new int[columnCount];

        if (!noMetadata) {
            if (hasGlobalSpec) {
                readString(in);
                readString(in);
            }
            for (int i = 0; i < columnCount; i++) {
                names[i] = readString(in);
                types[i] = readType(in);
            }
        } else {
            for (int i = 0; i < columnCount; i++) {
                names[i] = "col" + i;
                types[i] = TypeCodec.BLOB;
            }
        }

        int rowCount = in.readInt();
        ResultSet rs = new ResultSet();
        rs.columnNames = names;
        rs.columnTypes = types;
        for (int r = 0; r < rowCount; r++) {
            List<Object> row = new ArrayList<Object>(columnCount);
            for (int i = 0; i < columnCount; i++) {
                row.add(TypeCodec.readValue(in, types[i]));
            }
            rs.rows.add(row);
        }
        return rs;
    }

    private ResultSet parsePrepared(DataInputStream in) throws Exception {
        int idLen = in.readUnsignedShort();
        byte[] id = new byte[idLen];
        in.readFully(id);
        int flags = in.readInt();
        int columnCount = in.readInt();
        int pkCount = in.readInt();
        boolean hasGlobalSpec = (flags & ROWS_FLAG_GLOBAL_TABLE_SPEC) != 0;
        if (hasGlobalSpec) {
            readString(in); // keyspace name
            readString(in); // table name
        }
        for (int i = 0; i < columnCount; i++) {
            readString(in); // column name
            readType(in);   // column type
        }
        for (int i = 0; i < pkCount; i++) {
            in.readUnsignedShort(); // primary-key column index
        }
        return new ResultSet();
    }

    private int readType(DataInputStream in) throws Exception {
        int id = in.readUnsignedShort();
        if (id == TypeCodec.CUSTOM) {
            // Custom types carry their class name as a string after the id.
            readString(in);
        } else if (id == TypeCodec.LIST || id == TypeCodec.SET || id == TypeCodec.MAP) {
            // Collections carry their element type(s) after the id.
            int n = in.readUnsignedShort();
            for (int i = 0; i < n; i++) {
                readType(in);
            }
        }
        return id;
    }

    private String readString(DataInputStream in) throws Exception {
        int len = in.readUnsignedShort();
        byte[] b = new byte[len];
        in.readFully(b);
        return new String(b, StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws Exception {
        if (socket != null) {
            try { socket.close(); } catch (Exception ignore) { }
        }
    }

    public static final class ResultSet {
        public final List<List<Object>> rows = new ArrayList<List<Object>>();
        public String[] columnNames = new String[0];
        public int[] columnTypes = new int[0];

        public boolean isEmpty() {
            return rows.isEmpty();
        }
    }

    public static final class CassandraException extends RuntimeException {
        public final int code;
        public CassandraException(int code, String message) {
            super(message);
            this.code = code;
        }
    }
}
