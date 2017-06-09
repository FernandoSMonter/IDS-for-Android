package com.infotool;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.os.IBinder;
import android.os.SystemClock;
import android.support.annotation.Nullable;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import java.util.Date;

public class MainService extends Service {

    final static int ID_FOREGROUND_START = 1;

    Monitor monitor;

    BroadcastReceiver receiver;

    BroadcastReceiver notifyReceiver;

    static boolean running = false;


    @Override
    public void onCreate() {
        this.setReceiver();

        IntentFilter filter = new IntentFilter();
        filter.addAction("android.net.conn.CONNECTIVITY_CHANGE");

        this.setNotifyReceiver();
        IntentFilter notifyFilter = new IntentFilter();
        notifyFilter.addAction("com.infotool.NOTIFY_RESPONSE");


        registerReceiver(this.receiver, filter);
        registerReceiver(this.notifyReceiver, notifyFilter);

    }

    @Override
    public void onDestroy() {
        if( isMonitorRunning() )
        stopMonitor();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(ID_FOREGROUND_START, buildForegroundNotification("Iniciando", "Iniciando...") );

        running = true;
        return START_STICKY;
    }


    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }


    private void setNotification(String content, String ticker) {

        Notification notification = buildForegroundNotification(content, ticker);

        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        mNotificationManager.notify(ID_FOREGROUND_START, notification);
    }

    private Notification buildForegroundNotification(String content, String ticker) {

        PendingIntent pi = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), 0);

        NotificationCompat.Builder b = new NotificationCompat.Builder(this);

        b.setOngoing(true);

        b.setContentTitle(getString(R.string.service_notification_title))
                .setContentText(content)
                .setWhen(new Date().getTime())
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setTicker(ticker)
                .setContentIntent(pi);

        return(b.build());
    }

    private void startMonitor(){
        monitor = new Monitor(this);
        monitor.start();
    }

    private void stopMonitor(){
        monitor.kill();

    }

    private boolean isMonitorRunning(){
        if( monitor != null && monitor.isRunning() )
            return true;
        return false;
    }

    private void setReceiver(){
        this.receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String action = intent.getAction();
                 if(action.equals("android.net.conn.CONNECTIVITY_CHANGE")){
                    NetworkInfo info = intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_INFO);

                    if( info.isConnected() ){
                        if( isMonitorRunning() ){
                            stopMonitor();
                        }
                        startMonitor();

                        setNotification("Monitoreando red...", "Monitoreando");
                    }else {
                        if ( isMonitorRunning() ) {
                            stopMonitor();
                        }
                        setNotification("Esperando conexión...", "Sin conexión");
                    }
                }
            }
        };
    }

    public void setNotifyReceiver(){
        this.notifyReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
               Intent intentActivity = new Intent(context, ResponseActivity.class);
                intentActivity.putExtras(intent.getExtras());
                intentActivity.setFlags(intentActivity.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intentActivity);
            }
        };
    }


}
