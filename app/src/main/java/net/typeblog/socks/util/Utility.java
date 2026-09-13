package net.typeblog.socks.util;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.util.List;

import net.typeblog.socks.R;
import net.typeblog.socks.SocksVpnService;
import static net.typeblog.socks.util.Constants.*;

public class Utility {
    private static final String TAG = Utility.class.getSimpleName();

    public static int parsePort(String value) {
        if (value == null || !value.matches("[0-9]{1,5}")) return -1;
        int port = Integer.parseInt(value);
        return port >= 1 && port <= 65535 ? port : -1;
    }

    public static int exec(String... cmd) {
        try {
            Process p = new ProcessBuilder(cmd)
                    .redirectErrorStream(true)
                    .start();
            return p.waitFor();
        } catch (Exception e) {
            return -1;
        }
    }

    public static void killPidFile(String f) {
        File file = new File(f);

        if (!file.exists()) {
            return;
        }

        InputStream i;
        try {
            i = new FileInputStream(file);
        } catch (Exception e) {
            return;
        }

        byte[] buf = new byte[512];
        int len;
        StringBuilder str = new StringBuilder();

        try {
            while ((len = i.read(buf, 0, 512)) > 0) {
                str.append(new String(buf, 0, len));
            }
            i.close();
        } catch (Exception e) {
            return;
        }

        try {
            int pid = Integer.parseInt(str.toString().trim().replace("\n", ""));
            exec("kill", Integer.toString(pid));
            if(!file.delete())
                Log.w(TAG, "failed to delete pidfile");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String join(List<String> list, String separator) {
        if (list.isEmpty()) return "";

        StringBuilder ret = new StringBuilder();

        for (String s : list) {
            ret.append(s).append(separator);
        }

        return ret.substring(0, ret.length() - separator.length());
    }

    public static void makePdnsdConf(Context context, String dns, int port) throws IOException {
        String conf = context.getString(R.string.pdnsd_conf)
                .replace("{DIR}", context.getFilesDir().toString())
                .replace("{IP}", dns)
                .replace("{PORT}", Integer.toString(port));

        try (OutputStream out = new FileOutputStream(new File(context.getFilesDir(), "pdnsd.conf"))) {
            out.write(conf.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        File cache = new File(context.getFilesDir(), "pdnsd.cache");
        if (!cache.exists() && !cache.createNewFile()) {
            throw new IOException("Failed to create DNS cache");
        }
    }

    public static void startVpn(Context context, Profile profile) {
        startVpn(context, profile, 0L, false);
    }

    public static void startVpn(Context context, Profile profile, long startupDelayMs, boolean waitForNetwork) {
        Intent i = new Intent(context, SocksVpnService.class)
                .putExtra(INTENT_NAME, profile.getName())
                .putExtra(INTENT_SERVER, profile.getServer())
                .putExtra(INTENT_PORT, profile.getPort())
                .putExtra(INTENT_ROUTE, profile.getRoute())
                .putExtra(INTENT_DNS, profile.getDns())
                .putExtra(INTENT_DNS_PORT, profile.getDnsPort())
                .putExtra(INTENT_PER_APP, profile.isPerApp())
                .putExtra(INTENT_IPV6_PROXY, profile.hasIPv6())
                .putExtra(INTENT_STARTUP_DELAY_MS, startupDelayMs)
                .putExtra(INTENT_WAIT_FOR_NETWORK, waitForNetwork);

        if (profile.isUserPw()) {
            i.putExtra(INTENT_USERNAME, profile.getUsername())
                    .putExtra(INTENT_PASSWORD, profile.getPassword());
        }

        if (profile.isPerApp()) {
            i.putExtra(INTENT_APP_BYPASS, profile.isBypassApp())
                    .putExtra(INTENT_APP_LIST, profile.getAppList().split("\n"));
        }

        if (profile.hasUDP()) {
            i.putExtra(INTENT_UDP_GW, profile.getUDPGW());
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(i);
        } else {
            context.startService(i);
        }
    }
}
