package net.typeblog.socks.util;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.IDN;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Local DNS-over-TCP endpoint whose only upstream is the configured SOCKS5 server. */
public final class SocksDnsRelay implements Closeable {
    private static final Logger LOG = Logger.getLogger(SocksDnsRelay.class.getName());
    private static final int TIMEOUT_MS = 10_000;
    private final String proxyHost;
    private final int proxyPort;
    private final byte[] username;
    private final byte[] password;
    private final byte[] destination;
    private final int dnsPort;
    private final ServerSocket listener;
    private final Set<Socket> sockets = new HashSet<>();
    private final ThreadPoolExecutor workers = new ThreadPoolExecutor(0, 8, 30,
            TimeUnit.SECONDS, new SynchronousQueue<>());
    private final Thread acceptThread;
    private volatile boolean closed;

    public SocksDnsRelay(String proxyHost, int proxyPort, String username, String password,
                         String dnsHost, int dnsPort) throws IOException {
        if (proxyHost == null || proxyHost.isEmpty() || proxyPort < 1 || proxyPort > 65535
                || dnsPort < 1 || dnsPort > 65535) {
            throw new IOException("Invalid proxy address or DNS port");
        }
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.dnsPort = dnsPort;
        this.username = username == null ? null : credential(username);
        this.password = username == null ? null : credential(password);
        destination = destination(dnsHost);
        listener = new ServerSocket();
        try {
            listener.bind(new InetSocketAddress("127.0.0.1", 0), 8);
        } catch (IOException e) {
            listener.close();
            throw e;
        }
        acceptThread = new Thread(this::accept, "socks-dns");
        acceptThread.start();
    }

    public int getPort() {
        return listener.getLocalPort();
    }

    public boolean isRunning() {
        return !closed && acceptThread.isAlive();
    }

    private static byte[] credential(String value) throws IOException {
        byte[] bytes = value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 1 || bytes.length > 255) {
            throw new IOException("SOCKS credentials must contain 1 to 255 UTF-8 bytes");
        }
        return bytes;
    }

    private static byte[] destination(String host) throws IOException {
        if (host == null || host.isEmpty()) throw new IOException("Missing DNS address");
        // Only parse numeric IPv6 locally; hostnames are resolved by the SOCKS server.
        if (host.indexOf(':') >= 0) {
            byte[] address = InetAddress.getByName(host).getAddress();
            byte[] encoded = new byte[address.length + 1];
            encoded[0] = (byte) (address.length == 4 ? 1 : 4);
            java.lang.System.arraycopy(address, 0, encoded, 1, address.length);
            return encoded;
        }
        if (host.matches("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")) {
            byte[] encoded = new byte[5];
            encoded[0] = 1;
            String[] parts = host.split("\\.");
            for (int i = 0; i < 4; i++) {
                try {
                    int part = Integer.parseInt(parts[i]);
                    if (part > 255) throw new NumberFormatException();
                    encoded[i + 1] = (byte) part;
                } catch (NumberFormatException e) {
                    throw new IOException("Invalid DNS IPv4 address");
                }
            }
            return encoded;
        }
        final byte[] name;
        try {
            name = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).getBytes(StandardCharsets.US_ASCII);
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid DNS hostname", e);
        }
        if (name.length < 1 || name.length > 255) throw new IOException("Invalid DNS hostname length");
        byte[] encoded = new byte[name.length + 2];
        encoded[0] = 3;
        encoded[1] = (byte) name.length;
        java.lang.System.arraycopy(name, 0, encoded, 2, name.length);
        return encoded;
    }

    private synchronized boolean track(Socket socket) {
        if (closed) {
            closeSocket(socket);
            return false;
        }
        sockets.add(socket);
        return true;
    }

    private synchronized void release(Socket socket) {
        sockets.remove(socket);
        closeSocket(socket);
    }

    private void accept() {
        try {
            while (!closed) {
                Socket client = listener.accept();
                if (!track(client)) break;
                try {
                    workers.execute(() -> relay(client));
                } catch (RejectedExecutionException e) {
                    release(client);
                }
            }
        } catch (IOException e) {
            if (!closed) LOG.log(Level.WARNING, "DNS relay listener failed", e);
        } finally {
            close();
        }
    }

    private void relay(Socket client) {
        Socket upstream = new Socket(java.net.Proxy.NO_PROXY);
        try {
            if (!track(upstream)) return;
            client.setSoTimeout(TIMEOUT_MS);
            upstream.connect(new InetSocketAddress(proxyHost, proxyPort), TIMEOUT_MS);
            upstream.setSoTimeout(TIMEOUT_MS);
            DataInputStream remoteIn = new DataInputStream(upstream.getInputStream());
            DataOutputStream remoteOut = new DataOutputStream(upstream.getOutputStream());
            negotiate(remoteIn, remoteOut);
            DataInputStream localIn = new DataInputStream(client.getInputStream());
            DataOutputStream localOut = new DataOutputStream(client.getOutputStream());
            // pdnsd uses DNS-over-TCP framing. Keep exchanges bounded and allow connection reuse.
            while (!closed) {
                forwardMessage(localIn, remoteOut);
                forwardMessage(remoteIn, localOut);
            }
        } catch (EOFException e) {
            // Either peer closed its DNS connection.
        } catch (IOException e) {
            if (!closed) LOG.log(Level.FINE, "DNS request through SOCKS failed", e);
        } finally {
            release(upstream);
            release(client);
        }
    }

    private void negotiate(DataInputStream in, DataOutputStream out) throws IOException {
        int method = username == null ? 0 : 2;
        out.write(new byte[]{5, 1, (byte) method});
        out.flush();
        if (in.readUnsignedByte() != 5 || in.readUnsignedByte() != method) {
            throw new IOException("SOCKS authentication method rejected");
        }
        if (method == 2) {
            out.writeByte(1);
            out.writeByte(username.length);
            out.write(username);
            out.writeByte(password.length);
            out.write(password);
            out.flush();
            if (in.readUnsignedByte() != 1 || in.readUnsignedByte() != 0) {
                throw new IOException("SOCKS authentication failed");
            }
        }
        out.write(new byte[]{5, 1, 0});
        out.write(destination);
        out.writeShort(dnsPort);
        out.flush();
        if (in.readUnsignedByte() != 5 || in.readUnsignedByte() != 0 || in.readUnsignedByte() != 0) {
            throw new IOException("SOCKS DNS connection rejected");
        }
        int type = in.readUnsignedByte();
        int length;
        if (type == 1) length = 4;
        else if (type == 4) length = 16;
        else if (type == 3) length = in.readUnsignedByte();
        else throw new IOException("Invalid SOCKS address type");
        in.readFully(new byte[length + 2]);
    }

    private static void forwardMessage(DataInputStream in, DataOutputStream out) throws IOException {
        int length = in.readUnsignedShort();
        if (length < 12) throw new IOException("Invalid DNS message length");
        byte[] message = new byte[length];
        in.readFully(message);
        out.writeShort(length);
        out.write(message);
        out.flush();
    }

    private static void closeSocket(Socket socket) {
        try {
            socket.close();
        } catch (IOException e) {
            LOG.log(Level.FINE, "Failed to close DNS socket", e);
        }
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        try {
            listener.close();
        } catch (IOException e) {
            LOG.log(Level.FINE, "Failed to close DNS listener", e);
        }
        for (Socket socket : sockets) closeSocket(socket);
        sockets.clear();
        workers.shutdownNow();
    }
}
