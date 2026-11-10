package testes;

import client.*;
import comum.Wire;
import crypto.Crypto;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.security.*;
import java.util.*;

class SecurityTest {
    record Pair(PeerSession a,PeerSession b) {}
    Pair pair() throws Exception {
        var a=Crypto.ephemeral();var b=Crypto.ephemeral();UUID aid=UUID.randomUUID(),bid=UUID.randomUUID();byte[] salt=Crypto.random(16);
        return new Pair(new PeerSession(aid,bid,a.getPrivate(),Crypto.raw(b.getPublic()),salt),new PeerSession(bid,aid,b.getPrivate(),Crypto.raw(a.getPublic()),salt));
    }
    @Test void e2eBidirectionalAndLimit() throws Exception {
        var p=pair();assertEquals("Ola B",p.b.decrypt(p.a.encrypt("Ola B")));assertEquals("Ola A",p.a.decrypt(p.b.encrypt("Ola A")));
        assertEquals("x".repeat(4096),p.b.decrypt(p.a.encrypt("x".repeat(4096))));
        assertThrows(IllegalArgumentException.class,()->p.a.encrypt("é".repeat(2049)));
    }
    @Test void tamperingDoesNotAdvanceCounter() throws Exception {
        var p=pair();byte[] valid=p.a.encrypt("nao entregar adulterada"),changed=valid.clone();changed[changed.length-1]^=1;
        assertThrows(javax.crypto.AEADBadTagException.class,()->p.b.decrypt(changed));
        assertEquals("nao entregar adulterada",p.b.decrypt(valid));
    }
    @Test void replayRejected() throws Exception {
        var p=pair();byte[] frame=p.a.encrypt("uma vez");assertEquals("uma vez",p.b.decrypt(frame));
        assertEquals("Replay rejeitado",assertThrows(GeneralSecurityException.class,()->p.b.decrypt(frame)).getMessage());
    }
    @Test void framingRejectsInvalidAndTruncatedLengths() throws Exception {
        for(int n:new int[]{-1,0,Wire.MAX_FRAME+1,Integer.MAX_VALUE}) {
            byte[] prefix=Wire.pack(out->out.writeInt(n));assertThrows(IOException.class,()->Wire.read(new ByteArrayInputStream(prefix)));
        }
        assertThrows(EOFException.class,()->Wire.read(new ByteArrayInputStream(new byte[]{0,0})));
        assertThrows(EOFException.class,()->Wire.read(new ByteArrayInputStream(new byte[]{0,0,0,3,1})));
    }
    @Test void framingReadsFragmentedAndCoalescedFrames() throws Exception {
        var bytes=new ByteArrayOutputStream();Wire.write(bytes,new byte[]{1,2,3});Wire.write(bytes,new byte[]{4});
        var fragmented=new FilterInputStream(new ByteArrayInputStream(bytes.toByteArray())) {
            @Override public int read(byte[] b,int off,int len) throws IOException {return super.read(b,off,Math.min(1,len));}
        };
        assertArrayEquals(new byte[]{1,2,3},Wire.read(fragmented));assertArrayEquals(new byte[]{4},Wire.read(fragmented));
    }
    @Test void modifiedSignatureAndUntrustedKeyRejected() throws Exception {
        var gen=KeyPairGenerator.getInstance("RSA");gen.initialize(2048);var key=gen.generateKeyPair();var other=gen.generateKeyPair();
        byte[] body={1,2,3},sig=Crypto.sign(key.getPrivate(),body);Crypto.verify(key.getPublic(),body,sig);
        assertThrows(GeneralSecurityException.class,()->Crypto.verify(other.getPublic(),body,sig));sig[0]^=1;
        assertThrows(GeneralSecurityException.class,()->Crypto.verify(key.getPublic(),body,sig));
    }
}
