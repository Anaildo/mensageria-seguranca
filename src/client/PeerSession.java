package client;

import comum.Wire;
import crypto.Crypto;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.Cipher;

public final class PeerSession {
    private final UUID local, remote;
    private final byte[] sendKey, recvKey, base = Crypto.random(4);
    private byte[] recvBase;
    private long send = 0, received = -1;

    public PeerSession(UUID local, UUID remote, PrivateKey sk, byte[] peerKey, byte[] salt)
            throws GeneralSecurityException {
        this.local = local;
        this.remote = remote;
        boolean a = local.toString().compareTo(remote.toString()) < 0;
        byte[] z = Crypto.shared(sk, peerKey);
        try {
            sendKey = Crypto.derive(salt, z, a ? "A2B" : "B2A");
            recvKey = Crypto.derive(salt, z, a ? "B2A" : "A2B");
        } finally {
            Arrays.fill(z, (byte) 0);
        }
    }

    public synchronized byte[] encrypt(String text) throws GeneralSecurityException, IOException {
        byte[] plain = text.getBytes(StandardCharsets.UTF_8);
        if (plain.length > Wire.MAX_TEXT)
            throw new IllegalArgumentException("Limite: 4096 bytes UTF-8");
        if (send == Long.MAX_VALUE)
            throw new IllegalStateException("Reconecte para renovar a sessao");
        long seq = send++;
        byte[] nonce = ByteBuffer.allocate(12).put(base).putLong(seq).array();
        byte[] aad = Wire.pack(out -> {
            Wire.uuid(out, local);
            Wire.uuid(out, remote);
            out.writeLong(seq);
        });
        byte[] cipher = Crypto.gcm(Cipher.ENCRYPT_MODE, sendKey, nonce, aad, plain);
        return Wire.pack(out -> {
            out.write(nonce);
            out.write(aad);
            out.write(cipher);
        });
    }

    public synchronized String decrypt(byte[] frame) throws GeneralSecurityException, IOException {
        if (frame.length < 68 || frame.length > 4164)
            throw new IOException("Frame E2E invalido");
        var in = Wire.input(frame);
        byte[] nonce = Wire.exact(in, 12);
        UUID sender = Wire.uuid(in), recipient = Wire.uuid(in);
        long seq = in.readLong();
        if (!sender.equals(remote) || !recipient.equals(local))
            throw new GeneralSecurityException("Destinatario/remetente invalido");
        if (seq < 0 || seq <= received)
            throw new GeneralSecurityException("Replay rejeitado");
        if (ByteBuffer.wrap(nonce, 4, 8).getLong() != seq)
            throw new GeneralSecurityException("Nonce invalido");
        byte[] prefix = Arrays.copyOf(nonce, 4);
        if (recvBase != null && !Arrays.equals(prefix, recvBase))
            throw new GeneralSecurityException("IV invalido");
        byte[] plain = Crypto.gcm(Cipher.DECRYPT_MODE, recvKey, nonce, Arrays.copyOfRange(frame, 12, 52),
                in.readAllBytes());
        received = seq;
        recvBase = prefix;
        return new String(plain, StandardCharsets.UTF_8);
    }
}
