package net.typeblog.socks;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.util.Log;

import net.typeblog.socks.util.Profile;
import net.typeblog.socks.util.ProfileManager;
import net.typeblog.socks.util.Utility;
import static net.typeblog.socks.BuildConfig.DEBUG;
import static net.typeblog.socks.util.Constants.DEFAULT_STARTUP_WARMUP_DELAY_MS;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = BootReceiver.class.getSimpleName();

    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            Profile p = new ProfileManager(context).getDefault();

            if (p.autoConnect() && VpnService.prepare(context) == null) {

                if (DEBUG) {
                    Log.d(TAG, "starting VPN service on boot");
                }

                Utility.startVpn(context, p, DEFAULT_STARTUP_WARMUP_DELAY_MS, true);
            }
        }
    }
}
