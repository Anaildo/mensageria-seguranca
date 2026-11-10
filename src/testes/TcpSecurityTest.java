package testes;

import client.ClientMain;
import comum.Wire;
import server.ServerMain;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;

class TcpSecurityTest {
    @TempDir Path directory;
    Path store,cert;
    ServerMain server;
    Thread thread;
    final char[] password="academic-test-only".toCharArray();
    @BeforeEach void setup() throws Exception {
        store=directory.resolve("server.p12");cert=directory.resolve("server.crt");
        keytool("-genkeypair","-alias","server","-keyalg","RSA","-keysize","2048","-validity","2","-dname","CN=Test","-storetype","PKCS12","-keystore",store.toString(),"-storepass",new String(password));
        keytool("-exportcert","-alias","server","-keystore",store.toString(),"-storepass",new String(password),"-file",cert.toString());
        server=new ServerMain(0,store,password);
        thread=Thread.ofPlatform().start(()->{try{server.serve();}catch(IOException e){throw new UncheckedIOException(e);}});
    }
    void keytool(String... args) throws Exception {
        List<String> cmd=new ArrayList<>();cmd.add(Path.of(System.getProperty("java.home"),"bin","keytool").toString());cmd.addAll(List.of(args));
        var process=new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(directory.resolve("keytool.log").toFile()).start();
        assertTrue(process.waitFor(30,TimeUnit.SECONDS));assertEquals(0,process.exitValue());
    }
    @AfterEach void cleanup() throws Exception {if(server!=null)server.close();if(thread!=null)thread.join(3000);}
    ClientMain connect(UUID id,List<String> output) throws Exception {
        var client=new ClientMain("127.0.0.1",server.port(),cert,id,output::add);client.start();return client;
    }
    static void await(BooleanSupplier condition) throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);
        while(!condition.getAsBoolean() && System.nanoTime()<deadline) Thread.sleep(10);
        assertTrue(condition.getAsBoolean(),"Evento TCP nao observado dentro do prazo");
    }
    static boolean has(List<String> output,String text) {return output.stream().anyMatch(s->s.contains(text));}
    @Test void relayTamperReplayAndInvalidFramingIsolation() throws Exception {
        List<String> aOut=new CopyOnWriteArrayList<>(),bOut=new CopyOnWriteArrayList<>();
        try(var a=connect(UUID.randomUUID(),aOut);var b=connect(UUID.randomUUID(),bOut)) {
            await(()->a.participants().contains(b.id)&&b.participants().contains(a.id));
            a.send(b.id,"SEGREDO_APENAS_CLIENTE",false);await(()->has(bOut,"Recebida de "));
            a.replay();await(()->has(bOut,"Rejeitada: replay"));
            a.send(b.id,"NAO_DEVE_SER_ENTREGUE",true);await(()->has(bOut,"autenticacao GCM falhou"));
            assertFalse(has(bOut,"NAO_DEVE_SER_ENTREGUE"));
            try(var bad=new Socket("127.0.0.1",server.port())) {
                bad.setSoTimeout(3000);new DataOutputStream(bad.getOutputStream()).writeInt(-1);
                assertEquals(-1,bad.getInputStream().read());
            }
            b.send(a.id,"resposta apos framing invalido",false);await(()->has(aOut,"resposta apos framing invalido"));
        }
    }
    @Test void sameUuidReconnectRenewsSession() throws Exception {
        UUID aid=UUID.randomUUID();List<String> out=new CopyOnWriteArrayList<>();
        try(var b=connect(UUID.randomUUID(),new CopyOnWriteArrayList<>())) {
            try(var a=connect(aid,out)) {await(()->a.participants().contains(b.id));a.send(b.id,"antes",false);}
            await(()->!b.participants().contains(aid));
            try(var fresh=connect(aid,out)) {await(()->fresh.participants().contains(b.id)&&b.participants().contains(aid));b.send(aid,"sessao renovada",false);await(()->has(out,"sessao renovada"));}
        }
    }
    @Test void untrustedCertificateRejectedInHandshake() throws Exception {
        Path other=directory.resolve("other.p12"),otherCert=directory.resolve("other.crt");
        keytool("-genkeypair","-alias","server","-keyalg","RSA","-keysize","2048","-validity","2","-dname","CN=Other","-storetype","PKCS12","-keystore",other.toString(),"-storepass",new String(password));
        keytool("-exportcert","-alias","server","-keystore",other.toString(),"-storepass",new String(password),"-file",otherCert.toString());
        assertThrows(java.security.GeneralSecurityException.class,()->new ClientMain("127.0.0.1",server.port(),otherCert,UUID.randomUUID(),s->{}));
    }
    record Terminal(Process process,List<String> lines,BufferedWriter input) implements AutoCloseable {
        void command(String command) throws IOException {input.write(command);input.newLine();input.flush();}
        @Override public void close() throws Exception {
            input.close();process.destroy();if(!process.waitFor(3,TimeUnit.SECONDS))process.destroyForcibly();
        }
    }
    Terminal terminal(String main,String... args) throws IOException {
        List<String> command=new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"),"bin","java").toString());
        command.add("-Dfile.encoding=UTF-8");command.add("-cp");command.add(Path.of("target/classes").toAbsolutePath().toString());command.add(main);command.addAll(List.of(args));
        var builder=new ProcessBuilder(command).redirectErrorStream(true);
        builder.environment().put("MENSAGERIA_STORE_PASSWORD",new String(password));
        var process=builder.start();List<String> lines=new CopyOnWriteArrayList<>();
        Thread.ofVirtual().start(()->{try(var reader=process.inputReader(java.nio.charset.StandardCharsets.UTF_8)){reader.lines().forEach(lines::add);}catch(IOException e){lines.add("Falha ao ler processo");}});
        return new Terminal(process,lines,process.outputWriter(java.nio.charset.StandardCharsets.UTF_8));
    }
    @Test void threeTerminalProcessesAndServerLogPrivacy() throws Exception {
        try(var s=terminal("server.ServerMain","0",store.toString())) {
            await(()->has(s.lines,"TCP ouvindo na porta "));
            String port=s.lines.stream().filter(l->l.contains("TCP ouvindo na porta ")).findFirst().orElseThrow().replaceAll(".*porta ","");
            try(var a=terminal("client.ClientMain","127.0.0.1",port,cert.toString());
                var b=terminal("client.ClientMain","127.0.0.1",port,cert.toString())) {
                await(()->has(a.lines,"Participante disponivel")&&has(b.lines,"Participante disponivel"));
                String bid=b.lines.stream().filter(l->l.contains("Seu UUID: ")).findFirst().orElseThrow().replaceAll(".*Seu UUID: ","");
                a.command("listar");await(()->has(a.lines,"Participantes: 1"));
                a.command("enviar "+bid+" CONTEUDO_PRIVADO_123_ação");await(()->has(b.lines,"CONTEUDO_PRIVADO_123_ação"));
                a.command("demo-replay");await(()->has(b.lines,"Rejeitada: replay"));
                a.command("demo-adulterar "+bid+" TEXTO_ADULTERADO_456");await(()->has(b.lines,"autenticacao GCM falhou"));
                assertFalse(has(b.lines,"TEXTO_ADULTERADO_456"));
                a.command("demo-framing");await(()->has(a.lines,"Conexao encerrada"));await(()->has(b.lines,"Participante saiu"));
                a.command("");assertTrue(a.process.waitFor(3,TimeUnit.SECONDS));assertEquals(0,a.process.exitValue());
                b.command("sair");assertTrue(b.process.waitFor(3,TimeUnit.SECONDS));assertEquals(0,b.process.exitValue());
                assertFalse(has(s.lines,"CONTEUDO_PRIVADO"));assertFalse(has(s.lines,"TEXTO_ADULTERADO"));
                assertTrue(s.lines.stream().allMatch(l->l.startsWith("[servidor] ")));
                assertFalse(s.lines.stream().anyMatch(l->l.toLowerCase(Locale.ROOT).matches(".*(nonce|salt|private|secret|ciphertext).*")));
            }
        }
    }
}
