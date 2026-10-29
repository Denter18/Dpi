package org.gvcoder.nodpi;

import android.content.Intent;
import android.net.ProxyInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

/**
 * VPN-сервис, который не гонит трафик через себя, а только выставляет системный
 * HTTP-прокси (127.0.0.1:PORT) для приложений. Это позволяет использовать
 * локальный прокси NoDPI и в мобильной сети (LTE), где нельзя задать прокси в Wi-Fi.
 *
 * Параметры приходят строками (HOST, PORT), чтобы не зависеть от выбора перегрузки
 * Intent.putExtra при вызове из Python (pyjnius).
 */
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
            String h = intent.getStringExtra("HOST");
            if (h != null && !h.isEmpty()) {
                host = h;
            }
            String p = intent.getStringExtra("PORT");
            if (p != null) {
                try {
                    port = Integer.parseInt(p.trim());
                } catch (NumberFormatException ignored) {
                    // оставляем порт по умолчанию
                }
            }
        }

        startVpn(host, port);

        // START_NOT_STICKY: если процесс убьют, прокси на Python тоже умрёт, и
        // автоматически поднятый VPN указывал бы на несуществующий прокси.
        return START_NOT_STICKY;
    }

    private void startVpn(String host, int port) {
        if (vpnInterface != null) {
            return;
        }
        try {
            Builder builder = new Builder();
            builder.setSession("NoDPI v2.3 LTE Mode")
                   .setMtu(1500)
                   .addAddress("10.111.222.1", 32);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setHttpProxy(ProxyInfo.buildDirectProxy(host, port));
            }

            try {
                // Само приложение (локальный прокси) в VPN не заворачиваем,
                // иначе его исходящие соединения зациклятся на себя.
                builder.addDisallowedApplication(getPackageName());
            } catch (Exception ignored) {
                // пакет не найден - не критично
            }

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
        } catch (Exception ignored) {
            // уже закрыт
        }
        stopSelf();
    }

    @Override
    public void onRevoke() {
        // Пользователь отключил VPN в системных настройках.
        stopVpn();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
