package client;

import comum.Wire;
import crypto.Crypto;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public final class ClientMain implements AutoCloseable {
    public final UUID id;
    private final KeyPair keys;
    private final Socket socket;
    private final X509Certificate trusted;
    private final Map<UUID, PeerSession> peers = new LinkedHashMap<>();
    private final Map<UUID, byte[]> identities = new HashMap<>();
    private long adminSeq = -1;
    private volatile boolean running = true;
    private byte[] lastFrame;
    private final java.util.function.Consumer<String> display;

    public ClientMain(String host, int port, Path cert, UUID id, java.util.function.Consumer<String> display)
            throws Exception {
        this.id = id;
        this.display = display;
        keys = Crypto.ephemeral();
        try (var in = Files.newInputStream(cert)) {
            trusted = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        trusted.checkValidity();
        socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), 5000);
            socket.setSoTimeout(15000);
            Wire.write(socket.getOutputStream(), Wire.typed(Wire.REGISTER, Wire.pack(out -> {
                Wire.uuid(out, id);
                out.write(Crypto.raw(keys.getPublic()));
            })));
            var in = Wire.input(Wire.read(socket.getInputStream()));
            if (in.readUnsignedByte() != Wire.WELCOME)
                throw new IOException("Handshake esperado");
            byte[] receivedCert = Wire.blob(in), salt = Wire.exact(in, 16), signature = Wire.blob(in);
            Wire.end(in);
            if (!MessageDigest.isEqual(receivedCert, trusted.getEncoded()))
                throw new GeneralSecurityException("Certificado nao confiavel");
            byte[] material = Wire.pack(out -> {
                out.write(trusted.getPublicKey().getEncoded());
                out.write(Crypto.raw(keys.getPublic()));
                Wire.uuid(out, id);
                out.write(salt);
            });
            Crypto.verify(trusted.getPublicKey(), material, signature);
            socket.setSoTimeout(0);
        } catch (Exception e) {
            socket.close();
            throw e;
        }
    }

    public void start() {
        Thread.ofVirtual().start(this::receive);
    }

    private void receive() {
        try {
            while (running) {
                var in = Wire.input(Wire.read(socket.getInputStream()));
                int type = in.readUnsignedByte();
                if (type == Wire.PEERS)
                    update(in);
                else if (type == Wire.MESSAGE) {
                    byte[] frame = in.readAllBytes();
                    try {
                        var f = Wire.input(frame);
                        Wire.exact(f, 12);
                        UUID sender = Wire.uuid(f);
                        String text;
                        synchronized (this) {
                            var peer = peers.get(sender);
                            if (peer == null)
                                throw new GeneralSecurityException();
                            text = peer.decrypt(frame);
                        }
                        display.accept("[cliente] Recebida de " + sender + ": " + text);
                    } catch (javax.crypto.AEADBadTagException e) {
                        display.accept("[cliente] Rejeitada: autenticacao GCM falhou (adulteracao)");
                    } catch (GeneralSecurityException e) {
                        display.accept("[cliente] Rejeitada: " + ("Replay rejeitado".equals(e.getMessage()) ? "replay"
                                : "sessao ou campos invalidos"));
                    }
                } else if (type == Wire.ERROR) {
                    Wire.end(in);
                    display.accept("[cliente] Destinatario indisponivel");
                } else
                    throw new IOException("Controle invalido");
            }
        } catch (Exception e) {
            if (running)
                display.accept("[cliente] Conexao encerrada: transporte ou controle invalido");
        } finally {
            try {
                close();
            } catch (IOException e) {
                display.accept("[cliente] Falha ao fechar conexao");
            }
        }
    }

    private synchronized void update(DataInputStream packet) throws Exception {
        byte[] body = Wire.blob(packet), signature = Wire.blob(packet);
        Wire.end(packet);
        Crypto.verify(trusted.getPublicKey(), body, signature);
        var in = Wire.input(body);
        if (!Wire.uuid(in).equals(id) || !Arrays.equals(Wire.exact(in, 32), Crypto.raw(keys.getPublic())))
            throw new GeneralSecurityException();
        long seq = in.readLong();
        if (seq <= adminSeq)
            throw new GeneralSecurityException("Replay administrativo");
        int count = in.readInt();
        if (count < 1 || count > 64)
            throw new IOException();
        record Entry(byte[] key, byte[] salt) {
        }
        Map<UUID, Entry> entries = new LinkedHashMap<>();
        for (int i = 0; i < count; i++) {
            UUID peer = Wire.uuid(in);
            if (entries.put(peer, new Entry(Wire.exact(in, 32), Wire.exact(in, 16))) != null)
                throw new IOException();
        }
        Wire.end(in);
        if (!entries.containsKey(id))
            throw new IOException();
        Set<UUID> active = new HashSet<>(entries.keySet());
        active.remove(id);
        for (UUID old : new HashSet<>(peers.keySet()))
            if (!active.contains(old)) {
                peers.remove(old);
                identities.remove(old);
                display.accept("[cliente] Participante saiu: " + old);
            }
        for (UUID peer : active) {
            var e = entries.get(peer);
            byte[] salt = entries.get(id.toString().compareTo(peer.toString()) < 0 ? id : peer).salt();
            byte[] identity = Wire.pack(out -> {
                out.write(e.key());
                out.write(salt);
            });
            if (!Arrays.equals(identity, identities.get(peer))) {
                peers.put(peer, new PeerSession(id, peer, keys.getPrivate(), e.key(), salt));
                identities.put(peer, identity);
                display.accept("[cliente] Participante disponivel: " + peer);
            }
        }
        adminSeq = seq;
    }

    public synchronized Set<UUID> participants() {
        return Set.copyOf(peers.keySet());
    }

    public synchronized void send(UUID peer, String text, boolean tamper) throws Exception {
        var session = peers.get(peer);
        if (session == null)
            throw new IllegalArgumentException("UUID nao disponivel; use listar");
        byte[] frame = session.encrypt(text);
        lastFrame = frame.clone();
        if (tamper)
            frame[frame.length - 1] ^= 1;
        Wire.write(socket.getOutputStream(), Wire.typed(Wire.MESSAGE, frame));
        display.accept(tamper ? "[cliente] Demonstracao: frame adulterado enviado"
                : "[cliente] Mensagem enviada (sem confirmacao de entrega)");
    }

    public synchronized void replay() throws IOException {
        if (lastFrame == null)
            throw new IllegalArgumentException("Envie uma mensagem primeiro");
        Wire.write(socket.getOutputStream(), Wire.typed(Wire.MESSAGE, lastFrame));
        display.accept("[cliente] Demonstracao: ultimo frame reenviado");
    }

    public void invalidFrame() throws IOException {
        synchronized (socket.getOutputStream()) {
            new DataOutputStream(socket.getOutputStream()).writeInt(-1);
            socket.getOutputStream().flush();
        }
        display.accept("[cliente] Demonstracao: framing invalido enviado; servidor encerrara esta conexao");
    }

    @Override
    public void close() throws IOException {
        running = false;
        socket.close();
        synchronized (this) {
            peers.clear();
            identities.clear();
            lastFrame = null;
        }
    }

    private static void help() {
        System.out.println(
                "Comandos: listar | enviar <UUID> <texto> | sair | ajuda\nDemo: demo-adulterar <UUID> <texto> | demo-replay | demo-framing");
    }

    public static void main(String[] args) {
        System.setOut(new PrintStream(System.out, true, java.nio.charset.StandardCharsets.UTF_8));
        System.setErr(new PrintStream(System.err, true, java.nio.charset.StandardCharsets.UTF_8));
        if (args.length != 3) {
            System.out.println("Uso: ClientMain <host> <porta> <certs/server.crt>");
            return;
        }
        try (var client = new ClientMain(args[0], Integer.parseInt(args[1]), Path.of(args[2]), UUID.randomUUID(),
                System.out::println);
                var console = new BufferedReader(
                        new InputStreamReader(System.in, java.nio.charset.StandardCharsets.UTF_8))) {
            System.out.println("[cliente] Servidor autenticado. Seu UUID: " + client.id);
            help();
            client.start();
            String line;
            while (client.running && (line = console.readLine()) != null) {
                String[] parts = line.trim().split("\\s+", 3);
                try {
                    switch (parts[0]) {
                        case "listar" -> {
                            var peers = client.participants();
                            System.out.println("[cliente] Participantes: " + peers.size());
                            peers.stream().sorted().forEach(System.out::println);
                        }
                        case "enviar", "demo-adulterar" -> {
                            if (parts.length != 3)
                                throw new IllegalArgumentException("Uso: " + parts[0] + " <UUID> <texto>");
                            client.send(UUID.fromString(parts[1]), parts[2], parts[0].equals("demo-adulterar"));
                        }
                        case "demo-replay" -> client.replay();
                        case "demo-framing" -> client.invalidFrame();
                        case "ajuda" -> help();
                        case "sair" -> {
                            System.out.println("[cliente] Desconectado");
                            return;
                        }
                        case "" -> {
                        }
                        default -> System.out.println("[cliente] Comando desconhecido; use ajuda");
                    }
                } catch (IllegalArgumentException e) {
                    System.out.println("[cliente] " + e.getMessage());
                } catch (Exception e) {
                    System.out.println("[cliente] Nao foi possivel enviar; verifique a conexao");
                }
            }
        } catch (Exception e) {
            System.err.println("[cliente] Conexao/handshake recusado. Verifique host, porta e certificado confiavel.");
            System.exit(1);
        }
    }
}
