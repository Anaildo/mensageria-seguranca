package crypto;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;
import java.math.BigInteger;
import java.util.*;

public final class Crypto {
    private Crypto() {
    }

    public static byte[] random(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    public static KeyPair ephemeral() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    public static byte[] raw(PublicKey key) {
        byte[] be = ((XECPublicKey) key).getU().toByteArray(), le = new byte[32];
        for (int i = 0; i < 32 && i < be.length; i++)
            le[i] = be[be.length - 1 - i];
        return le;
    }

    public static PublicKey publicKey(byte[] raw) throws GeneralSecurityException {
        if (raw.length != 32)
            throw new InvalidKeyException();
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++)
            be[i] = raw[31 - i];
        return KeyFactory.getInstance("X25519")
                .generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, new BigInteger(1, be)));
    }

    public static byte[] shared(PrivateKey sk, byte[] pk) throws GeneralSecurityException {
        var k = KeyAgreement.getInstance("X25519");
        k.init(sk);
        k.doPhase(publicKey(pk), true);
        return k.generateSecret();
    }

    public static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    public static byte[] derive(byte[] salt, byte[] z, String label) throws GeneralSecurityException {
        byte[] prk = hmac(salt, z);
        try {
            return Arrays.copyOf(hmac(prk, (label + "\u0001").getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
                    16);
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    private static Signature pss() throws GeneralSecurityException {
        var s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        return s;
    }

    public static byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
        var s = pss();
        s.initSign(key);
        s.update(MessageDigest.getInstance("SHA-256").digest(data));
        return s.sign();
    }

    public static void verify(PublicKey key, byte[] data, byte[] signature) throws GeneralSecurityException {
        var s = pss();
        s.initVerify(key);
        s.update(MessageDigest.getInstance("SHA-256").digest(data));
        if (!s.verify(signature))
            throw new SignatureException("Assinatura invalida");
    }

    public static byte[] gcm(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] data)
            throws GeneralSecurityException {
        var c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad);
        return c.doFinal(data);
    }
}
