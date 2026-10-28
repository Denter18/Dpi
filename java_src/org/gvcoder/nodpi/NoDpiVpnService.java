package org.gvcoder.nodpi;

import android.content.Intent;
import android.net.ProxyInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

public class NoDpiVpnService extends VpnService {
    private ParcelFileDescriptor vpnInterface = null;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "STOP".equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }
        String host = "127.0.0.1";
        int port = 8881;
        if (intent != null) {
            if (intent.hasExtra("HOST")) host = intent.getStringExtra("HOST");
            if (intent.hasExtra("PORT")) port = intent.getIntExtra("PORT", 8881);
        }
        startVpn(host, port);
        return START_STICKY;
    }

    private void startVpn(String host, int port) {
        if (vpnInterface != null) return;
        try {
            Builder builder = new Builder();
            builder.setSession("NoDPI v2.3 LTE Mode")
                   .setMtu(1500)
                   .addAddress("10.111.222.1", 32); // Фиктивный локальный адрес интерфейса

            // Главная фича для LTE (Android 10+): глобальный системный HTTP-прокси
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setHttpProxy(ProxyInfo.buildDirectProxy(host, port));
            }

            // Исключаем само приложение NoDPI из VPN, чтобы не было бесконечной петли трафика
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (Exception ignored) {}

            vpnInterface = builder.establish();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void stopVpn() {
        try {
            if (vpnInterface != null) {
                vpnInterface.close();
                vpnInterface = null;
            }
        } catch (Exception ignored) {}
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
