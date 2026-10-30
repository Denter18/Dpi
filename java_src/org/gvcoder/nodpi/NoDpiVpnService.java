package org.gvcoder.nodpi;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

/**
 * VPN-сервис NoDPI. Поднимает TUN-интерфейс с маршрутом 0.0.0.0/0 и отдаёт его
 * файловый дескриптор Python-части (tunnel.py): весь IPv4-трафик устройства
 * идёт через локальный движок, ничего настраивать в Wi-Fi/браузере не нужно.
 *
 * Адреса согласованы с tunnel.py: TUN_ADDR = 10.111.222.1, PEER_ADDR (он же DNS
 * для приложений) = 10.111.222.2. IPv6 не маршрутизируется: у туннеля нет
 * IPv6-адреса, поэтому приложения сразу переходят на IPv4.
 *
 * Движок вызывает protectSocket() для каждого своего исходящего сокета, чтобы
 * его соединения шли мимо туннеля, а не зацикливались на самих себя.
 */
public class NoDpiVpnService extends VpnService {
    private static final String CHANNEL_ID = "nodpi_vpn";

    private static volatile NoDpiVpnService instance = null;
    private static volatile int tunFd = -1;

    private ParcelFileDescriptor vpnInterface = null;

    /** Дескриптор TUN или -1, пока интерфейс не поднят. Вызывается из Python. */
    public static int getTunFd() {
        return tunFd;
    }

    /** Вывести сокет из VPN. Вызывается из Python для каждого исходящего сокета. */
    public static boolean protectSocket(int fd) {
        NoDpiVpnService service = instance;
        return service != null && service.protect(fd);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "STOP".equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }

        showForegroundNotification();
        startVpn();

        // START_NOT_STICKY: если процесс убьют, Python-движок тоже умрёт, и
        // автоматически поднятый VPN без движка отрезал бы устройство от сети.
        return START_NOT_STICKY;
    }

    private void showForegroundNotification() {
        // Уведомление защищает процесс от остановки системой, пока VPN включён.
        try {
            Notification.Builder builder;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                NotificationManager manager =
                        (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
                manager.createNotificationChannel(new NotificationChannel(
                        CHANNEL_ID, "NoDPI", NotificationManager.IMPORTANCE_LOW));
                builder = new Notification.Builder(this, CHANNEL_ID);
            } else {
                builder = new Notification.Builder(this);
            }

            Notification notification = builder
                    .setContentTitle("NoDPI работает")
                    .setContentText("Трафик идёт через обход DPI")
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setOngoing(true)
                    .build();

            startForeground(1, notification);
        } catch (Exception ignored) {
            // без уведомления VPN всё равно работает
        }
    }

    private void startVpn() {
        if (vpnInterface != null) {
            return;
        }
        try {
            Builder builder = new Builder();
            builder.setSession("NoDPI")
                   .setMtu(1400)
                   .addAddress("10.111.222.1", 24)
                   .addRoute("0.0.0.0", 0)
                   .addDnsServer("10.111.222.2");

            vpnInterface = builder.establish();

            if (vpnInterface != null) {
                tunFd = vpnInterface.getFd();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void stopVpn() {
        tunFd = -1;
        try {
            if (vpnInterface != null) {
                vpnInterface.close();
                vpnInterface = null;
            }
        } catch (Exception ignored) {
            // уже закрыт
        }
        try {
            stopForeground(true);
        } catch (Exception ignored) {
            // не было foreground
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
        instance = null;
        super.onDestroy();
    }
}
