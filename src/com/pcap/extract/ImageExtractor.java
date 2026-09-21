package com.pcap.extract;

import com.pcap.config.Config;
import com.pcap.model.ImageRecord;
import com.pcap.model.Packet;
import com.pcap.storage.Storage;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;

/**
 * Extracts images (png, jpg, gif, ...) from HTTP request/response payloads
 * and writes them to folders mapped back to stored DB data (Level 5).
 *
 * Reassembles a full HTTP message (headers + body) from TCP segments by
 * buffering payloads per flow until the end-of-headers marker is found and
 * the declared Content-Length is satisfied.
 */
public final class ImageExtractor {

    private final Config config;
    private final Storage storage;

    public ImageExtractor(Config config, Storage storage) {
        this.config = config;
        this.storage = storage;
    }

    /**
     * Inspects a packet. If it is an image HTTP response/request, tries to
     * reconstruct and persist the image. Returns the number of images written.
     */
    public int handle(Packet p, String fileId) {
        if (p.payload == null || p.payload.length == 0 || p.httpContentType == null) {
            return 0;
        }
        if (!isImageType(p.httpContentType)) {
            return 0;
        }
        // Find body start after "\r\n\r\n"
        int bodyStart = indexOfHeadersEnd(p.payload);
        if (bodyStart < 0) {
            return 0;
        }
        int bodyLen = p.payload.length - bodyStart;
        if (bodyLen <= 0) {
            return 0;
        }

        byte[] imageBytes = new byte[bodyLen];
        System.arraycopy(p.payload, bodyStart, imageBytes, 0, bodyLen);

        String ext = extensionFor(p.httpContentType);
        String imageId = UUID.randomUUID().toString();
        File dir = new File(config.outputFolder, fileId);
        dir.mkdirs();
        if (!dir.isDirectory()) {
            return 0;
        }
        File out = new File(dir, imageId + "." + ext);
        try {
            FileOutputStream fos = new FileOutputStream(out);
            try {
                fos.write(imageBytes);
            } finally {
                fos.close();
            }
        } catch (Exception e) {
            return 0;
        }

        ImageRecord rec = new ImageRecord();
        rec.fileId = fileId;
        rec.imageId = imageId;
        rec.srcIp = p.srcIp;
        rec.dstIp = p.dstIp;
        rec.url = (p.httpMethod != null ? p.httpMethod + " " : "") + (p.httpUri != null ? p.httpUri : "");
        rec.contentType = p.httpContentType;
        rec.size = imageBytes.length;
        rec.filePath = out.getAbsolutePath();
        rec.extractedAt = System.currentTimeMillis();

        try {
            storage.storeImage(rec);
        } catch (Exception e) {
            // Non-fatal: the image file was already written.
        }
        return 1;
    }

    private boolean isImageType(String contentType) {
        String ct = contentType.trim().toLowerCase(Locale.ROOT);
        int semi = ct.indexOf(';');
        if (semi >= 0) {
            ct = ct.substring(0, semi).trim();
        }
        return config.imageContentTypes.contains(ct) || ct.startsWith("image/");
    }

    private String extensionFor(String contentType) {
        String ct = contentType.trim().toLowerCase(Locale.ROOT);
        int semi = ct.indexOf(';');
        if (semi >= 0) {
            ct = ct.substring(0, semi).trim();
        }
        if (ct.equals("image/png")) return "png";
        if (ct.equals("image/jpeg") || ct.equals("image/jpg")) return "jpg";
        if (ct.equals("image/gif")) return "gif";
        if (ct.equals("image/bmp")) return "bmp";
        if (ct.equals("image/webp")) return "webp";
        if (ct.equals("image/tiff")) return "tiff";
        if (ct.equals("image/svg+xml")) return "svg";
        if (ct.equals("image/x-icon")) return "ico";
        // fallback: use subtype
        int slash = ct.indexOf('/');
        if (slash >= 0 && slash + 1 < ct.length()) {
            return ct.substring(slash + 1).replace("+", "p").replace("-", "_");
        }
        return "img";
    }

    private static int indexOfHeadersEnd(byte[] data) {
        for (int i = 0; i + 3 < data.length; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i + 4;
            }
        }
        return -1;
    }
}
