package net.typeblog.socks;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;

import net.typeblog.socks.util.Profile;
import net.typeblog.socks.util.ProfileManager;
import net.typeblog.socks.util.Routes;
import net.typeblog.socks.util.SocksDnsRelay;
import net.typeblog.socks.util.Utility;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import static net.typeblog.socks.BuildConfig.DEBUG;
import static net.typeblog.socks.util.Constants.*;

public class SocksVpnService extends VpnService {
    class VpnBinder extends IVpnService.Stub {
        @Override
        public boolean isRunning() {
            return mRunning;
        }

        @Override
        public void stop() {
            stopMe();
        }
    }

    private static final String TAG = SocksVpnService.class.getSimpleName();
    private static final long WATCHDOG_INTERVAL_MS = 3000;
    private static final long NETWORK_RECONNECT_DELAY_MS = 2000;
    private static final long NETWORK_WAIT_TIMEOUT_MS = 10_000;
    private static final long NETWORK_WAIT_POLL_MS = 500;
    private static final long RESTART_BACKOFF_BASE_MS = 2000;
    private static final long RESTART_BACKOFF_MAX_MS = 60_000;

    private String STATUS_FILE;

    private int mRestartCount = 0;
    private int mConsecutiveFailures = 0;
    private long mStartTime = 0;

    private ParcelFileDescriptor mInterface;
    private volatile SocksDnsRelay mDnsRelay;
    private volatile boolean mRunning = false;
    private volatile boolean mTunnelConnected = false;
    private volatile boolean mWatchdogStarted = false;
    private final IBinder mBinder = new VpnBinder();
    private final Object mStatusLock = new Object();

    private volatile boolean mWaitForNetwork = false;

    // Stored params for restart
    private String mServer;
    private int mPort;
    private String mUsername;
    private String mPassword;
    private String mDns;
    private String mUdpgw;
    private int mDnsPort;
    private boolean mIpv6;

    private volatile ExecutorService mTunnelExecutor;
    private final AtomicBoolean mTunnelTaskRunning = new AtomicBoolean(false);
    private final AtomicBoolean mRestartScheduled = new AtomicBoolean(false);

    // Watchdog/restart scheduler
    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private Runnable mPendingTunnelStartRunnable;
    private boolean mPendingTunnelStartIsRestart = false;
    private final Runnable mWatchdog = new Runnable() {
        @Override
        public void run() {
            if (!mRunning) return;

            if (mTunnelTaskRunning.get()) {
                mHandler.postDelayed(this, WATCHDOG_INTERVAL_MS);
                return;
            }
            SocksDnsRelay relay = mDnsRelay;
            boolean alive = isDaemonAlive("tun2socks") && isDaemonAlive("pdnsd")
                    && relay != null && relay.isRunning();
            if (alive) {
                mTunnelConnected = true;
                mConsecutiveFailures = 0;
                writeStatus("connected");
            } else {
                if (mTunnelConnected) {
                    Log.w(TAG, "tunnel or DNS helper died, scheduling restart");
                }
                mTunnelConnected = false;
                writeStatus("reconnecting");
                scheduleTunnelStart(Math.max(WATCHDOG_INTERVAL_MS, computeRestartBackoffMs()), true, "watchdog");
            }

            mHandler.postDelayed(this, WATCHDOG_INTERVAL_MS);
        }
    };

    // Network change listener
    private ConnectivityManager.NetworkCallback mNetworkCallback;
    private volatile Network mLastUpstreamNetwork = null;
    private boolean mIgnoreFirstCallback = true;

    @Override
    public void onCreate() {
        super.onCreate();
        STATUS_FILE = getFilesDir() + "/jorkproxy_status";
        mTunnelExecutor = Executors.newSingleThreadExecutor();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (DEBUG) {
            Log.d(TAG, "starting");
        }

        if (mRunning) {
            return START_STICKY;
        }

        final String name;
        final String server;
        final int port;
        final String username;
        final String passwd;
        final String route;
        final String dns;
        final int dnsPort;
        final boolean perApp;
        final boolean appBypass;
        final String[] appList;
        final boolean ipv6;
        final String udpgw;
        final long startupDelayMs;
        final boolean waitForNetwork;

        // Check if intent has our extras (normal start) or not (system always-on restart).
        if (intent != null && intent.hasExtra(INTENT_NAME)) {
            name = intent.getStringExtra(INTENT_NAME);
            server = intent.getStringExtra(INTENT_SERVER);
            port = intent.getIntExtra(INTENT_PORT, 1080);
            username = intent.getStringExtra(INTENT_USERNAME);
            passwd = intent.getStringExtra(INTENT_PASSWORD);
            route = intent.getStringExtra(INTENT_ROUTE);
            dns = intent.getStringExtra(INTENT_DNS);
            dnsPort = intent.getIntExtra(INTENT_DNS_PORT, 53);
            perApp = intent.getBooleanExtra(INTENT_PER_APP, false);
            appBypass = intent.getBooleanExtra(INTENT_APP_BYPASS, false);
            appList = intent.getStringArrayExtra(INTENT_APP_LIST);
            ipv6 = intent.getBooleanExtra(INTENT_IPV6_PROXY, false);
            udpgw = intent.getStringExtra(INTENT_UDP_GW);
            startupDelayMs = Math.max(0L, intent.getLongExtra(INTENT_STARTUP_DELAY_MS, 0L));
            waitForNetwork = intent.getBooleanExtra(INTENT_WAIT_FOR_NETWORK, false);
        } else {
            // System always-on VPN restart or null intent: load profile and apply warmup/network wait.
            Log.i(TAG, "no extras in intent, loading saved profile");
            Profile profile = new ProfileManager(this).getDefault();
            name = profile.getName();
            server = profile.getServer();
            port = profile.getPort();
            username = profile.isUserPw() ? profile.getUsername() : null;
            passwd = profile.isUserPw() ? profile.getPassword() : null;
            route = profile.getRoute();
            dns = profile.getDns();
            dnsPort = profile.getDnsPort();
            perApp = profile.isPerApp();
            appBypass = profile.isBypassApp();
            appList = profile.isPerApp() ? profile.getAppList().split("\n") : null;
            ipv6 = profile.hasIPv6();
            udpgw = profile.hasUDP() ? profile.getUDPGW() : null;
            startupDelayMs = DEFAULT_STARTUP_WARMUP_DELAY_MS;
            waitForNetwork = true;
        }

        // Notifications on Oreo and above need a channel.
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= 26) {
            String notificationChannelId = "com.jork.proxy";
            NotificationChannel channel = new NotificationChannel(notificationChannelId,
                    getString(R.string.channel_name), NotificationManager.IMPORTANCE_NONE);
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            Objects.requireNonNull(notificationManager).createNotificationChannel(channel);
            builder = new Notification.Builder(this, notificationChannelId);
        } else {
            builder = new Notification.Builder(this);
        }

        // Create the foreground notification.
        int notificationId = 1;
        int intentFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            intentFlags |= PendingIntent.FLAG_IMMUTABLE;
        }

        PendingIntent contentIntent = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), intentFlags);
        startForeground(notificationId, builder
                .setContentTitle(getString(R.string.notify_title))
                .setContentText(String.format(getString(R.string.notify_msg), name))
                .setPriority(Notification.PRIORITY_MIN)
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentIntent(contentIntent)
                .build());

        // Build TUN interface.
        if (!configure(name, route, perApp, appBypass, appList, ipv6)) {
            Log.e(TAG, "failed to establish VPN interface");
            stopMe();
            return START_NOT_STICKY;
        }

        if (DEBUG && mInterface != null) {
            Log.d(TAG, "fd: " + mInterface.getFd());
        }

        cacheTunnelConfig(server, port, username, passwd, dns, dnsPort, ipv6, udpgw);

        mRunning = true;
        mTunnelConnected = false;
        mWaitForNetwork = waitForNetwork;
        mStartTime = java.lang.System.currentTimeMillis();
        mRestartCount = 0;
        mConsecutiveFailures = 0;
        mRestartScheduled.set(false);
        mWatchdogStarted = false;
        clearPendingTunnelStart();
        mTunnelTaskRunning.set(false);

        if (mTunnelExecutor == null || mTunnelExecutor.isShutdown()) {
            mTunnelExecutor = Executors.newSingleThreadExecutor();
        }

        writeStatus("starting");
        registerNetworkCallback();

        mHandler.removeCallbacks(mWatchdog);
        scheduleTunnelStart(startupDelayMs, false, "initial-start");
        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        super.onRevoke();
        stopMe();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopMe();
    }

    private void stopMe() {
        mRunning = false;
        mTunnelConnected = false;
        mWaitForNetwork = false;
        mWatchdogStarted = false;
        writeStatus("stopped");

        mHandler.removeCallbacks(mWatchdog);
        clearPendingTunnelStart();
        mRestartScheduled.set(false);
        mTunnelTaskRunning.set(false);
        unregisterNetworkCallback();

        if (mTunnelExecutor != null) {
            mTunnelExecutor.shutdownNow();
            mTunnelExecutor = null;
        }

        stopForeground(true);

        stopDnsRelay();
        Utility.killPidFile(getFilesDir() + "/tun2socks.pid");
        Utility.killPidFile(getFilesDir() + "/pdnsd.pid");

        if (mInterface != null) {
            try {
                mInterface.close();
            } catch (Exception e) {
                Log.w(TAG, "failed to close vpn interface", e);
            }
            mInterface = null;
        }

        stopSelf();
    }

    private boolean configure(String name, String route, boolean perApp, boolean bypass, String[] apps, boolean ipv6) {
        Builder b = new Builder();
        b.setMtu(1500)
                .setSession(name)
                .addAddress("26.26.26.1", 24)
                .addDnsServer("1.1.1.1");

        if (ipv6) {
            // Route all IPv6 traffic.
            b.addAddress("fdfe:dcba:9876::1", 126)
                    .addRoute("::", 0);
        }

        Routes.addRoutes(this, b, TextUtils.isEmpty(route) ? ROUTE_ALL : route);

        // This DNS is a stub, real DNS requests are redirected through pdnsd.
        b.addRoute("1.1.1.1", 32);

        String[] safeApps = apps == null ? new String[0] : apps;

        if (!perApp) {
            try {
                b.addDisallowedApplication("com.jork.proxy");
            } catch (Exception e) {
                Log.w(TAG, "failed to disallow self package", e);
            }
        } else if (bypass) {
            try {
                b.addDisallowedApplication("com.jork.proxy");
            } catch (Exception e) {
                Log.w(TAG, "failed to disallow self package", e);
            }

            for (String p : safeApps) {
                if (TextUtils.isEmpty(p)) continue;
                try {
                    b.addDisallowedApplication(p.trim());
                } catch (Exception e) {
                    Log.w(TAG, "failed to disallow package: " + p, e);
                }
            }
        } else {
            for (String p : safeApps) {
                if (TextUtils.isEmpty(p) || "com.jork.proxy".equals(p.trim())) {
                    continue;
                }
                try {
                    b.addAllowedApplication(p.trim());
                } catch (Exception e) {
                    Log.w(TAG, "failed to allow package: " + p, e);
                }
            }
        }

        mInterface = b.establish();
        return mInterface != null;
    }

    private void cacheTunnelConfig(String server, int port, String user, String passwd, String dns,
                                   int dnsPort, boolean ipv6, String udpgw) {
        mServer = server;
        mPort = port;
        mUsername = user;
        mPassword = passwd;
        mDns = dns;
        mDnsPort = dnsPort;
        mIpv6 = ipv6;
        mUdpgw = udpgw;
    }

    private void clearPendingTunnelStart() {
        if (mPendingTunnelStartRunnable != null) {
            mHandler.removeCallbacks(mPendingTunnelStartRunnable);
            mPendingTunnelStartRunnable = null;
        }
        if (mPendingTunnelStartIsRestart) {
            mRestartScheduled.set(false);
        }
        mPendingTunnelStartIsRestart = false;
    }

    private void ensureWatchdogRunning() {
        mHandler.post(() -> {
            if (!mRunning || mWatchdogStarted) return;
            mWatchdogStarted = true;
            mHandler.postDelayed(mWatchdog, WATCHDOG_INTERVAL_MS);
        });
    }

    private void scheduleTunnelStart(long delayMs, boolean restart, String reason) {
        if (!mRunning) return;

        if (restart) {
            if (mTunnelTaskRunning.get()) return;
            if (!mRestartScheduled.compareAndSet(false, true)) return;
        }

        clearPendingTunnelStart();

        Runnable r = new Runnable() {
            @Override
            public void run() {
                if (mPendingTunnelStartRunnable == this) {
                    mPendingTunnelStartRunnable = null;
                    mPendingTunnelStartIsRestart = false;
                }
                if (restart) {
                    mRestartScheduled.set(false);
                }
                if (!mRunning) return;
                startTunnelAsync(restart, reason);
            }
        };
        mPendingTunnelStartRunnable = r;
        mPendingTunnelStartIsRestart = restart;

        if (delayMs <= 0) {
            mHandler.post(r);
        } else {
            mHandler.postDelayed(r, delayMs);
        }
    }

    private void startTunnelAsync(boolean restart, String reason) {
        if (!mRunning) return;
        ExecutorService executor = mTunnelExecutor;
        if (executor == null || executor.isShutdown()) return;
        if (!mTunnelTaskRunning.compareAndSet(false, true)) return;

        try {
            executor.execute(() -> {
                try {
                    if (!mRunning || mInterface == null) return;

                    if (mWaitForNetwork && findUpstreamNetwork() == null
                            && !waitForUpstreamNetwork(NETWORK_WAIT_TIMEOUT_MS)) {
                        onTunnelAttemptFailed(reason + ": no upstream network");
                        return;
                    }

                    if (restart) {
                        mRestartCount++;
                        Utility.killPidFile(getFilesDir() + "/tun2socks.pid");
                        Utility.killPidFile(getFilesDir() + "/pdnsd.pid");
                    }

                    boolean started = startTunnel(mInterface.getFd());
                    if (!mRunning) return;

                    if (started) {
                        mTunnelConnected = true;
                        mConsecutiveFailures = 0;
                        writeStatus("connected");
                        if (DEBUG) {
                            Log.d(TAG, "tunnel started: " + reason);
                        }
                    } else {
                        onTunnelAttemptFailed(reason + ": tunnel failed to initialize");
                    }
                } finally {
                    if (!mRunning) {
                        stopDnsRelay();
                        Utility.killPidFile(getFilesDir() + "/tun2socks.pid");
                        Utility.killPidFile(getFilesDir() + "/pdnsd.pid");
                    }
                    mTunnelTaskRunning.set(false);
                    ensureWatchdogRunning();
                }
            });
        } catch (RejectedExecutionException e) {
            mTunnelTaskRunning.set(false);
            if (mRunning) {
                Log.w(TAG, "tunnel executor rejected task", e);
            }
        }
    }

    private void onTunnelAttemptFailed(String reason) {
        if (!mRunning) return;
        mTunnelConnected = false;
        mConsecutiveFailures++;
        long delay = computeRestartBackoffMs();
        Log.w(TAG, "tunnel start/restart failed (" + reason + "), retry in " + delay + "ms");
        writeStatus("reconnecting");
    }

    private long computeRestartBackoffMs() {
        long delay = RESTART_BACKOFF_BASE_MS;
        int steps = Math.max(0, mConsecutiveFailures - 1);
        for (int i = 0; i < steps; i++) {
            if (delay >= RESTART_BACKOFF_MAX_MS / 2) {
                return RESTART_BACKOFF_MAX_MS;
            }
            delay *= 2;
        }
        return Math.min(delay, RESTART_BACKOFF_MAX_MS);
    }

    private boolean waitForUpstreamNetwork(long timeoutMs) {
        long deadline = SystemClock.elapsedRealtime() + timeoutMs;
        while (mRunning) {
            Network network = findUpstreamNetwork();
            if (network != null) {
                mLastUpstreamNetwork = network;
                return true;
            }

            if (SystemClock.elapsedRealtime() >= deadline) {
                return false;
            }

            SystemClock.sleep(NETWORK_WAIT_POLL_MS);
        }
        return false;
    }

    private Network findUpstreamNetwork() {
        ConnectivityManager cm = getConnectivityManager();
        if (cm == null) return null;

        for (Network network : cm.getAllNetworks()) {
            if (isUsableUpstreamNetwork(cm, network)) {
                return network;
            }
        }
        return null;
    }

    private boolean isUsableUpstreamNetwork(ConnectivityManager cm, Network network) {
        if (network == null) return false;
        NetworkCapabilities caps = cm.getNetworkCapabilities(network);
        return caps != null
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }

    private synchronized boolean startDnsRelay() {
        stopDnsRelay();
        if (!mRunning) return false;
        try {
            mDnsRelay = new SocksDnsRelay(mServer, mPort, mUsername, mPassword, mDns, mDnsPort);
            Utility.makePdnsdConf(this, "127.0.0.1", mDnsRelay.getPort());
            return true;
        } catch (IOException e) {
            Log.e(TAG, "failed to initialize DNS relay", e);
            stopDnsRelay();
            return false;
        }
    }

    private synchronized void stopDnsRelay() {
        if (mDnsRelay != null) {
            mDnsRelay.close();
            mDnsRelay = null;
        }
    }

    private boolean startTunnel(int fd) {
        if (!startDnsRelay()) return false;

        String nativeDir = getApplicationInfo().nativeLibraryDir;
        String filesDir = getFilesDir().toString();
        String dataDir = getApplicationInfo().dataDir;

        int pdnsdExit = Utility.exec(
                nativeDir + "/libpdnsd.so",
                "-c",
                filesDir + "/pdnsd.conf"
        );
        if (pdnsdExit != 0) {
            Log.e(TAG, "pdnsd failed to start (exit=" + pdnsdExit + ")");
            return false;
        }

        List<String> cmd = new ArrayList<>();
        cmd.add(nativeDir + "/libtun2socks.so");
        cmd.add("--netif-ipaddr");
        cmd.add("26.26.26.2");
        cmd.add("--netif-netmask");
        cmd.add("255.255.255.0");
        cmd.add("--socks-server-addr");
        cmd.add(String.format(Locale.US, "%s:%d", mServer, mPort));
        cmd.add("--tunfd");
        cmd.add(Integer.toString(fd));
        cmd.add("--tunmtu");
        cmd.add("1500");
        cmd.add("--loglevel");
        cmd.add("3");
        cmd.add("--pid");
        cmd.add(filesDir + "/tun2socks.pid");
        cmd.add("--sock");
        cmd.add(dataDir + "/sock_path");
        cmd.add("--dnsgw");
        cmd.add("26.26.26.1:8091");

        if (!TextUtils.isEmpty(mUsername) && mPassword != null) {
            cmd.add("--username");
            cmd.add(mUsername);
            cmd.add("--password");
            cmd.add(mPassword);
        }

        if (mIpv6) {
            cmd.add("--netif-ip6addr");
            cmd.add("fdfe:dcba:9876::2");
        }

        if (!TextUtils.isEmpty(mUdpgw)) {
            cmd.add("--udpgw-remote-server-addr");
            cmd.add(mUdpgw);
        }

        if (DEBUG) {
            Log.d(TAG, String.format(Locale.US,
                    "starting tun2socks server=%s:%d ipv6=%s udp=%s auth=%s",
                    mServer,
                    mPort,
                    mIpv6,
                    !TextUtils.isEmpty(mUdpgw),
                    !TextUtils.isEmpty(mUsername)));
        }

        int tun2socksExit = Utility.exec(cmd.toArray(new String[0]));
        if (tun2socksExit != 0) {
            Log.e(TAG, "tun2socks failed to start (exit=" + tun2socksExit + ")");
            return false;
        }

        for (int i = 1; i <= 5 && mRunning; i++) {
            if (System.sendfd(fd, dataDir + "/sock_path") != -1) {
                return true;
            }
            SystemClock.sleep(1000L * i);
        }

        return false;
    }

    private boolean isDaemonAlive(String name) {
        File pidFile = new File(getFilesDir() + "/" + name + ".pid");
        if (!pidFile.exists()) return false;

        try {
            byte[] buf = new byte[64];
            java.io.FileInputStream fis = new java.io.FileInputStream(pidFile);
            int len = fis.read(buf);
            fis.close();
            if (len <= 0) return false;

            int pid = Integer.parseInt(new String(buf, 0, len).trim());
            if (pid <= 0) return false;
            try (java.io.FileInputStream cmdline = new java.io.FileInputStream("/proc/" + pid + "/cmdline")) {
                byte[] command = new byte[4096];
                int count = cmdline.read(command);
                if (count <= 0) return false;
                int end = 0;
                while (end < count && command[end] != 0) end++;
                return new String(command, 0, end, java.nio.charset.StandardCharsets.UTF_8)
                        .equals(getApplicationInfo().nativeLibraryDir + "/lib" + name + ".so");
            }
        } catch (Exception e) {
            return false;
        }
    }

    private ConnectivityManager getConnectivityManager() {
        return (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
    }

    private boolean isVpnNetwork(Network network) {
        ConnectivityManager cm = getConnectivityManager();
        if (cm == null || network == null) return false;
        NetworkCapabilities caps = cm.getNetworkCapabilities(network);
        return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }

    private void registerNetworkCallback() {
        ConnectivityManager cm = getConnectivityManager();
        if (cm == null) return;

        mLastUpstreamNetwork = findUpstreamNetwork();
        mIgnoreFirstCallback = true;

        mNetworkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                if (!mRunning || isVpnNetwork(network)) return;

                if (mIgnoreFirstCallback) {
                    mIgnoreFirstCallback = false;
                    if (mLastUpstreamNetwork != null && mLastUpstreamNetwork.equals(network)) {
                        return;
                    }
                }

                if (mLastUpstreamNetwork != null && mLastUpstreamNetwork.equals(network)) {
                    return;
                }

                mLastUpstreamNetwork = network;
                if (!mTunnelConnected) {
                    // During startup/reconnect we only track network changes; the worker handles connection.
                    return;
                }
                Log.i(TAG, "upstream network changed, scheduling tunnel restart");
                scheduleTunnelStart(NETWORK_RECONNECT_DELAY_MS, true, "network-change");
            }

            @Override
            public void onLost(Network network) {
                if (!mRunning || isVpnNetwork(network)) return;
                if (!network.equals(mLastUpstreamNetwork)) return;
                mLastUpstreamNetwork = null;
                mTunnelConnected = false;
                writeStatus("reconnecting");
                Log.i(TAG, "upstream network lost, waiting for connectivity");
            }
        };

        try {
            cm.registerDefaultNetworkCallback(mNetworkCallback);
        } catch (Exception e) {
            Log.w(TAG, "failed to register network callback", e);
            mNetworkCallback = null;
        }
    }

    private void unregisterNetworkCallback() {
        if (mNetworkCallback == null) return;

        ConnectivityManager cm = getConnectivityManager();
        if (cm != null) {
            try {
                cm.unregisterNetworkCallback(mNetworkCallback);
            } catch (Exception ignored) {
                // Already unregistered.
            }
        }
        mNetworkCallback = null;
    }

    private void writeStatus(String state) {
        synchronized (mStatusLock) {
            try {
                long uptime = mStartTime > 0 ? (java.lang.System.currentTimeMillis() - mStartTime) / 1000 : 0;
                String status = String.format(Locale.US,
                        "state=%s\nserver=%s:%d\nuptime=%d\nrestarts=%d\ntimestamp=%d\n",
                        state,
                        mServer != null ? mServer : "none", mPort,
                        uptime,
                        mRestartCount,
                        java.lang.System.currentTimeMillis() / 1000);
                java.io.FileOutputStream fos = new java.io.FileOutputStream(STATUS_FILE);
                fos.write(status.getBytes());
                fos.close();
                android.system.Os.chmod(STATUS_FILE, 0600);
            } catch (Exception e) {
                Log.w(TAG, "failed to write status file", e);
            }
        }
    }
}
