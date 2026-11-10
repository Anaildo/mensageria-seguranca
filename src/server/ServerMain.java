package server;

import comum.Wire;
import crypto.Crypto;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;

public final class ServerMain implements AutoCloseable {
    private final ServerSocket listener;
    private final PrivateKey signing;
    private final X509Certificate certificate;
    private final Map<UUID, Session> sessions = new LinkedHashMap<>();
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
    private volatile boolean closed;
    private static final int MAX_CLIENTS = 64;

    private static final class Session {
        final UUID id;
        final byte[] key, salt;
        final OutputStream out;
        long seq;

        Session(UUID id, byte[] key, byte[] salt, OutputStream out) {
            this.id = id;
            this.key = key;
            this.salt = salt;
            this.out = out;
        }
    }

    public ServerMain(int port, Path store, char[] password) throws Exception {
        var ks = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(store)) {
            ks.load(in, password);
        }
        signing = (PrivateKey) ks.getKey("server", password);
        certificate = (X509Certificate) ks.getCertificate("server");
        certificate.checkValidity();
        if (!(certificate.getPublicKey() instanceof java.security.interfaces.RSAPublicKey rsa)
                || rsa.getModulus().bitLength() < 2048)
            throw new GeneralSecurityException("RSA >=2048 necessario");
        listener = new ServerSocket(port);
    }

    public int port() {
        return listener.getLocalPort();
    }

    public void serve() throws IOException {
        System.out.println("[servidor] TCP ouvindo na porta " + port());
        while (!closed) {
            try {
                Socket s = listener.accept();
                if (sockets.size() >= MAX_CLIENTS) {
                    s.close();
                    System.out.println("[servidor] Limite de conexoes atingido");
                    continue;
                }
                sockets.add(s);
                workers.submit(() -> handle(s));
            } catch (SocketException e) {
                if (!closed)
                    throw e;
            }
        }
    }

    private void handle(Socket socket) {
        Session session = null;
        System.out.println("[servidor] Conexao TCP aceita");
        try (socket) {
            socket.setSoTimeout(15000);
            var in = Wire.input(Wire.read(socket.getInputStream()));
            if (in.readUnsignedByte() != Wire.REGISTER)
                throw new IOException("Registro esperado");
            UUID id = Wire.uuid(in);
            if (id.version() != 4 || id.variant() != 2)
                throw new IOException("UUID v4 esperado");
            byte[] key = Wire.exact(in, 32);
            Wire.end(in);
            Crypto.publicKey(key);
            session = new Session(id, key, Crypto.random(16), socket.getOutputStream());
            synchronized (this) {
                if (sessions.containsKey(id))
                    throw new IOException("UUID ja conectado");
                byte[] salt = session.salt;
                byte[] material = Wire.pack(out -> {
                    out.write(certificate.getPublicKey().getEncoded());
                    out.write(key);
                    Wire.uuid(out, id);
                    out.write(salt);
                });
                byte[] sig = Crypto.sign(signing, material), cert = certificate.getEncoded();
                Wire.write(session.out, Wire.typed(Wire.WELCOME, Wire.pack(out -> {
                    Wire.blob(out, cert);
                    out.write(salt);
                    Wire.blob(out, sig);
                })));
                sessions.put(id, session);
                broadcast();
            }
            socket.setSoTimeout(0);
            System.out.println("[servidor] Registrado " + id);
            while (true) {
                byte[] packet = Wire.read(socket.getInputStream());
                if (packet[0] != Wire.MESSAGE)
                    throw new IOException("Tipo invalido");
                byte[] frame = Arrays.copyOfRange(packet, 1, packet.length);
                if (frame.length < 68 || frame.length > 4164)
                    throw new IOException("Tamanho E2E invalido");
                var data = Wire.input(frame);
                Wire.exact(data, 12);
                UUID sender = Wire.uuid(data), recipient = Wire.uuid(data);
                if (!sender.equals(id))
                    throw new IOException("Remetente invalido");
                synchronized (this) {
                    var target = sessions.get(recipient);
                    if (target == null)
                        Wire.write(session.out, Wire.typed(Wire.ERROR, new byte[0]));
                    else {
                        try {
                            Wire.write(target.out, packet);
                        } catch (IOException failure) {
                            System.out.println("[servidor] Destinatario indisponivel " + recipient);
                            continue;
                        }
                        System.out
                                .println("[servidor] Relay " + sender + " -> " + recipient + " bytes=" + frame.length);
                    }
                }
            }
        } catch (EOFException e) {
            System.out.println("[servidor] Conexao encerrada ou frame truncado");
        } catch (Exception e) {
            System.out.println("[servidor] Conexao rejeitada: protocolo/framing ou falha de transporte");
        } finally {
            sockets.remove(socket);
            synchronized (this) {
                if (session != null && sessions.remove(session.id, session)) {
                    System.out.println("[servidor] Desconectado " + session.id);
                    broadcast();
                }
            }
        }
    }

    private synchronized void broadcast() {
        for (Session receiver : sessions.values()) {
            try {
                byte[] body = Wire.pack(out -> {
                    Wire.uuid(out, receiver.id);
                    out.write(receiver.key);
                    out.writeLong(receiver.seq++);
                    out.writeInt(sessions.size());
                    for (Session s : sessions.values()) {
                        Wire.uuid(out, s.id);
                        out.write(s.key);
                        out.write(s.salt);
                    }
                });
                byte[] signature = Crypto.sign(signing, body);
                Wire.write(receiver.out, Wire.typed(Wire.PEERS, Wire.pack(out -> {
                    Wire.blob(out, body);
                    Wire.blob(out, signature);
                })));
            } catch (Exception e) {
                System.out.println("[servidor] Falha na atualizacao de participantes " + receiver.id);
            }
        }
    }

    @Override
    public void close() throws IOException {
        closed = true;
        listener.close();
        for (Socket s : sockets)
            s.close();
        workers.shutdownNow();
    }

    public static void main(String[] args) {
        System.setOut(new PrintStream(System.out, true, java.nio.charset.StandardCharsets.UTF_8));
        System.setErr(new PrintStream(System.err, true, java.nio.charset.StandardCharsets.UTF_8));
        if (args.length != 2) {
            System.out.println("Uso: ServerMain <porta> <certs/server.p12>; senha em MENSAGERIA_STORE_PASSWORD");
            return;
        }
        String password = System.getenv("MENSAGERIA_STORE_PASSWORD");
        if (password == null) {
            System.out.println("Defina MENSAGERIA_STORE_PASSWORD");
            return;
        }
        try (var server = new ServerMain(Integer.parseInt(args[0]), Path.of(args[1]), password.toCharArray())) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    server.close();
                } catch (IOException e) {
                    System.err.println("[servidor] Falha ao encerrar");
                }
            }));
            server.serve();
        } catch (Exception e) {
            System.err.println("[servidor] Falha ao iniciar ou atender TCP. Verifique porta, certificado e senha.");
            System.exit(1);
        }
    }
}
