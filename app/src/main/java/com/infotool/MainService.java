package com.infotool;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.os.IBinder;
import android.os.SystemClock;
import android.support.annotation.IntDef;
import android.support.annotation.Nullable;
import android.support.v4.app.NotificationCompat;
import android.util.Log;
import android.widget.Toast;

import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.Date;

public class MainService extends Service {

    final static int ID_FOREGROUND_START = 1;

    Monitor monitor;

    BroadcastReceiver receiver;

    public MainService() {
    }

    @Override
    public void onCreate() {
        this.setReceiver();

        IntentFilter filter = new IntentFilter();
        filter.addAction("android.net.conn.CONNECTIVITY_CHANGE");
        filter.addAction("android.net.wifi.WIFI_STATE_CHANGED");
        registerReceiver(this.receiver, filter);
    }

    @Override
    public void onDestroy() {
        stopMonitor();
    }

    @Override
    public int onStartCommand(Intent intent,int flags, int startId) {
        startForeground(ID_FOREGROUND_START, buildForegroundNotification());

        return START_STICKY;
    }


    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private Notification buildForegroundNotification() {
        NotificationCompat.Builder b = new NotificationCompat.Builder(this);

        b.setOngoing(true);

        b.setContentTitle("Running in foreground")
                .setContentText("")
                .setWhen(SystemClock.currentThreadTimeMillis())
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setTicker("Starting");

        return(b.build());
    }

    private void startMonitor(){
        monitor = new Monitor();
        monitor.start();

        Log.e("Monitor","Starting Monitor module");
    }

    private void stopMonitor(){
        monitor.kill();

        Log.e("Monitor","Stopping Monitor module");
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
                if(action.equals("android.net.wifi.WIFI_STATE_CHANGED")){
                    //action for sms received
                   Log.e("Wifi","WIFI CHANGED");
                }
                else if(action.equals("android.net.conn.CONNECTIVITY_CHANGE")){

                    NetworkInfo info = intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_INFO);

                    if( info.isConnected() ){
                        if( isMonitorRunning() ){
                            stopMonitor();
                        }
                        startMonitor();
                    }else {
                        if ( isMonitorRunning() ) {
                            stopMonitor();
                        }
                    }
                    Log.e("Conn",info.isConnected() + "");
                }
            }
        };
    }
}
