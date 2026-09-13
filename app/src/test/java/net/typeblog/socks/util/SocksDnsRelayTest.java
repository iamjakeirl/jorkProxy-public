package net.typeblog.socks.util;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** Standalone JVM socket tests; no Android runtime or external proxy is needed. */
public final class SocksDnsRelayTest {
    private interface Peer {
        void run(DataInputStream in, DataOutputStream out) throws Exception;
    }

    private static final class Proxy implements AutoCloseable {
        final ServerSocket server = new ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"));
        final CompletableFuture<Void> done = new CompletableFuture<>();

        Proxy(Peer peer) throws IOException {
            server.setSoTimeout(5000);
            new Thread(() -> {
                try (Socket socket = server.accept()) {
                    socket.setSoTimeout(5000);
                    peer.run(new DataInputStream(socket.getInputStream()),
                            new DataOutputStream(socket.getOutputStream()));
                    done.complete(null);
                } catch (Throwable e) {
                    done.completeExceptionally(e);
                }
            }, "fake-socks").start();
        }

        SocksDnsRelay relay(String user, String password, String host, int port) throws IOException {
            return new SocksDnsRelay("127.0.0.1", server.getLocalPort(), user, password, host, port);
        }

        void await() throws Exception {
            done.get(6, TimeUnit.SECONDS);
        }

        public void close() throws IOException {
            server.close();
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static byte[] read(DataInputStream in, int count) throws IOException {
        byte[] bytes = new byte[count];
        in.readFully(bytes);
        return bytes;
    }

    private static void expect(DataInputStream in, byte[] expected) throws IOException {
        check(Arrays.equals(read(in, expected.length), expected), "Unexpected wire bytes");
    }

    private static Socket client(SocksDnsRelay relay) throws IOException {
        Socket socket = new Socket("127.0.0.1", relay.getPort());
        socket.setSoTimeout(5000);
        return socket;
    }

    private static void handshake(DataInputStream in, DataOutputStream out, boolean auth,
                                  byte[] address, int port, int replyType) throws Exception {
        expect(in, new byte[]{5, 1, (byte) (auth ? 2 : 0)});
        out.write(new byte[]{5, (byte) (auth ? 2 : 0)});
        out.flush();
        if (auth) {
            check(in.readUnsignedByte() == 1, "Authentication version");
            check(new String(read(in, in.readUnsignedByte()), StandardCharsets.UTF_8).equals("user"), "Username");
            check(new String(read(in, in.readUnsignedByte()), StandardCharsets.UTF_8).equals("pass"), "Password");
            out.write(new byte[]{1, 0});
            out.flush();
        }
        expect(in, new byte[]{5, 1, 0});
        expect(in, address);
        check(in.readUnsignedShort() == port, "DNS port must be preserved");
        out.write(new byte[]{5, 0, 0, (byte) replyType});
        if (replyType == 3) out.write(new byte[]{1, 'x'});
        else out.write(new byte[replyType == 1 ? 4 : 16]);
        out.writeShort(1234);
        out.flush();
    }

    private static void roundTrip(boolean auth, String dns, byte[] address, int replyType) throws Exception {
        byte[] query = new byte[32];
        query[0] = 42;
        byte[] answer = query.clone();
        answer[2] = (byte) 0x80;
        try (Proxy proxy = new Proxy((in, out) -> {
            handshake(in, out, auth, address, 5353, replyType);
            for (int i = 0; i < 2; i++) {
                check(in.readUnsignedShort() == query.length, "Query length");
                expect(in, query);
                out.writeShort(answer.length);
                // Exercise partial reads rather than assuming one read equals one DNS message.
                for (byte b : answer) {
                    out.writeByte(b);
                    out.flush();
                }
            }
        }); SocksDnsRelay relay = proxy.relay(auth ? "user" : null, auth ? "pass" : null, dns, 5353);
             Socket client = client(relay)) {
            DataInputStream in = new DataInputStream(client.getInputStream());
            DataOutputStream out = new DataOutputStream(client.getOutputStream());
            for (int i = 0; i < 2; i++) {
                out.writeShort(query.length);
                out.write(query);
                out.flush();
                check(in.readUnsignedShort() == answer.length, "Answer length");
                expect(in, answer);
            }
            proxy.await();
        }
    }

    private static void noFallback(boolean rejectAuthentication) throws Exception {
        try (ServerSocket directDns = new ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"));
             Proxy proxy = new Proxy((in, out) -> {
                 expect(in, new byte[]{5, 1, 2});
                 out.write(new byte[]{5, 2});
                 out.flush();
                 check(in.readUnsignedByte() == 1, "Authentication version");
                 read(in, in.readUnsignedByte());
                 read(in, in.readUnsignedByte());
                 out.write(new byte[]{1, (byte) (rejectAuthentication ? 1 : 0)});
                 out.flush();
                 if (!rejectAuthentication) {
                     expect(in, new byte[]{5, 1, 0, 1, 127, 0, 0, 1});
                     in.readUnsignedShort();
                     out.write(new byte[]{5, 5, 0, 1, 0, 0, 0, 0, 0, 0});
                     out.flush();
                 }
                 check(in.read() == -1, "Rejected connection must close");
             });
             SocksDnsRelay relay = proxy.relay("user", "pass", "127.0.0.1", directDns.getLocalPort());
             Socket client = client(relay)) {
            check(client.getInputStream().read() == -1, "DNS client must fail closed");
            proxy.await();
            directDns.setSoTimeout(250);
            try (Socket ignored = directDns.accept()) {
                throw new AssertionError("DNS bypassed SOCKS");
            } catch (SocketTimeoutException expected) {
                // No direct connection to the resolver.
            }
        }
    }

    private static void closeDuringHandshake() throws Exception {
        CompletableFuture<Void> greeting = new CompletableFuture<>();
        try (Proxy proxy = new Proxy((in, out) -> {
            expect(in, new byte[]{5, 1, 0});
            greeting.complete(null);
            check(in.read() == -1, "Shutdown must close upstream socket");
        }); SocksDnsRelay relay = proxy.relay(null, null, "1.1.1.1", 53);
             Socket client = client(relay)) {
            greeting.get(5, TimeUnit.SECONDS);
            relay.close();
            relay.close();
            check(!relay.isRunning(), "Stopped relay must not report running");
            check(client.getInputStream().read() == -1, "Shutdown must close local socket");
            proxy.await();
        }
    }

    private static void invalidConfiguration() throws Exception {
        for (int port : new int[]{0, -1, 65536}) {
            try (SocksDnsRelay ignored = new SocksDnsRelay("127.0.0.1", 1080, null, null, "1.1.1.1", port)) {
                throw new AssertionError("Invalid port accepted");
            } catch (IOException expected) { }
        }
        for (String password : new String[]{null, "", new String(new char[256]).replace('\0', 'x')}) {
            try (SocksDnsRelay ignored = new SocksDnsRelay("127.0.0.1", 1080, "user", password, "1.1.1.1", 53)) {
                throw new AssertionError("Invalid credentials accepted");
            } catch (IOException expected) { }
        }
    }

    public static void main(String[] args) throws Exception {
        roundTrip(false, "1.1.1.1", new byte[]{1, 1, 1, 1, 1}, 1);
        byte[] name = "dns.invalid".getBytes(StandardCharsets.US_ASCII);
        byte[] domain = new byte[name.length + 2];
        domain[0] = 3;
        domain[1] = (byte) name.length;
        java.lang.System.arraycopy(name, 0, domain, 2, name.length);
        roundTrip(true, "dns.invalid", domain, 3);
        byte[] ipv6 = new byte[17];
        ipv6[0] = 4;
        ipv6[16] = 1;
        roundTrip(false, "::1", ipv6, 4);
        noFallback(true);
        noFallback(false);
        closeDuringHandshake();
        invalidConfiguration();
        java.lang.System.out.println("PASS: DNS relay round trips, authentication, IPv4/IPv6/domain addressing, failure isolation, shutdown, validation");
    }
}
