package com.infotool;

import android.app.Activity;
import android.provider.Settings;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;


/**
 * Created by Fernando Sánchez on 16/04/2017.
 */

public class Tcpdump extends Thread{

    final String binaryPath = "./data/local/tcpdump";
    Activity activity;

    DataInputStream inputStream;
    DataOutputStream outputStream;

    Process su;

    public Tcpdump(Activity activity ){
        this.activity = activity;
    }

    @Override
    public void run() {
        this.startCapturing();
        showToast("Empezando captura");
        byte[] instream = new byte[8];

        try{
            this.sleep(5000);
            BufferedReader bufferedReader = new BufferedReader(
                    new InputStreamReader(su.getInputStream()));

            // Grab the results
            StringBuilder log = new StringBuilder();
            String line;
            try{
                Log.e("Read", bufferedReader.read() + "");
            }catch(IOException e){
                e.printStackTrace();
            }

            stopCapturing();
            showToast("Captura detenida");
            //this.interrupt();
            new Analyzer(activity);
        }catch (InterruptedException e){
            showToast("Error en sleep");
        }
    }

    /**
     * Runs TCPDump with root permission
     */
    public void startCapturing(){
        try{
            su = Runtime.getRuntime().exec("su");
            inputStream = new DataInputStream(su.getInputStream());
            outputStream = new DataOutputStream(su.getOutputStream());

            outputStream.writeBytes(this.binaryPath + "tcp -w /sdcard/infpackets/packets.pcap\n");

        }catch(IOException e){
            System.out.println(e.getStackTrace());
        }
    }

    public boolean runCommand(String command){
        try{
            outputStream.writeBytes(command);
            outputStream.flush();
            return true;
        }catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Stops a Tpcdump process which is currently running.
     */
    public void stopCapturing() {
        if ( runCommand("killall tcpdump") )
          closeShell();
    }

    /**
     * Destroys su Process Thread shell
     */
    public void closeShell(){
        su.destroy();
    }

    public void showToast(String message){
        final String msg = message;
        this.activity.runOnUiThread(new Runnable(){

            @Override
            public void run() {
                Toast.makeText(activity, msg, Toast.LENGTH_SHORT).show();
            }
        });
    }
}
