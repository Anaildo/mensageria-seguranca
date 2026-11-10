package comum;

import java.io.*;
import java.util.UUID;

public final class Wire {
    public static final int MAX_FRAME = 65536, MAX_TEXT = 4096;
    public static final int REGISTER = 1, WELCOME = 2, PEERS = 3, MESSAGE = 4, ERROR = 5;

    private Wire() {
    }

    @FunctionalInterface
    public interface Encoder {
        void write(DataOutputStream out) throws IOException;
    }

    public static byte[] pack(Encoder action) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(bytes)) {
            action.write(out);
        }
        return bytes.toByteArray();
    }

    public static DataInputStream input(byte[] data) {
        return new DataInputStream(new ByteArrayInputStream(data));
    }

    public static byte[] exact(DataInputStream in, int n) throws IOException {
        if (n < 0 || n > MAX_FRAME)
            throw new IOException("Comprimento invalido");
        byte[] b = in.readNBytes(n);
        if (b.length != n)
            throw new EOFException("Frame truncado");
        return b;
    }

    public static byte[] read(InputStream source) throws IOException {
        var in = new DataInputStream(source);
        int first = in.read();
        if (first < 0)
            throw new EOFException("Conexao encerrada");
        int n = (first << 24) | (in.readUnsignedByte() << 16) | (in.readUnsignedByte() << 8) | in.readUnsignedByte();
        if (n < 1 || n > MAX_FRAME)
            throw new IOException("Framing invalido");
        return exact(in, n);
    }

    public static void write(OutputStream target, byte[] data) throws IOException {
        if (data.length < 1 || data.length > MAX_FRAME)
            throw new IOException("Framing invalido");
        synchronized (target) {
            var out = new DataOutputStream(target);
            out.writeInt(data.length);
            out.write(data);
            out.flush();
        }
    }

    public static void blob(DataOutputStream out, byte[] b) throws IOException {
        out.writeInt(b.length);
        out.write(b);
    }

    public static byte[] blob(DataInputStream in) throws IOException {
        return exact(in, in.readInt());
    }

    public static void uuid(DataOutputStream out, UUID id) throws IOException {
        out.writeLong(id.getMostSignificantBits());
        out.writeLong(id.getLeastSignificantBits());
    }

    public static UUID uuid(DataInputStream in) throws IOException {
        return new UUID(in.readLong(), in.readLong());
    }

    public static void end(DataInputStream in) throws IOException {
        if (in.available() != 0)
            throw new IOException("Campos excedentes");
    }

    public static byte[] typed(int type, byte[] body) throws IOException {
        return pack(out -> {
            out.writeByte(type);
            out.write(body);
        });
    }
}
