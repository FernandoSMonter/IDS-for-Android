package com.infotool;

import android.app.Activity;
import android.os.Handler;
import android.provider.Settings;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Date;


/**
 * Created by Fernando Sánchez on 16/04/2017.
 */

public class Tcpdump extends Thread{

    final String binaryPath = "./data/local/tcpdump";
    Activity activity;

    DataInputStream inputStream;
    DataOutputStream outputStream;

    Handler refreshRate;

    Process su;

    Date time;

    public Tcpdump(Activity activity ){
        this.activity = activity;
       //refreshRate = new Handler();
    }

    @Override
    public void run() {
        File capture;

        showToast("Empezando captura");
        Log.e("Start", "Starting tcpdump");

        //Opens the shell with root
        this.openSuShell();

        //Starts tcpdump
        this.startCapturing();

        boolean analyzing = true;
        Date now;

        Log.e("Analyzing","Analyzing...");

        while ( analyzing ){
            now = new Date();
            if( now.getTime() > time.getTime() + 11000 ){
              // stopCapturing();

                capture = new File("/sdcard/infpackets/capture.pcap");

                    //The capture has packets inside
                if( capture.exists() && capture.length() > 0 ){
                    Log.e("Time", "11 seconds elapsed, starting analysis module");
                    Log.e("Capture", "Capture size: " + capture.length());
                    makeCopy(capture, "analyze.pcap");

                    Log.e("Analyze","Analyze.pcap replaced");
                    /*if( runCommand("cp /sdcard/infpackets/capture.pcap /sdcard/infpackets/analyze.pcap\n") )
                        Log.e("Copied","File copied");
                    else
                        Log.e("Copied", "Error copying file");*/

                    //new Analyzer(activity, new Date().getTime()).start();
                    //analyzing = false;
                    //closeShell();
                  //  startCapturing();
                    time = new Date();
                }else{
                    Log.e("Packet","Capture size: " + capture.length());
                   // startCapturing();
                    //No packet captured, wait for next capture update time
                    time = new Date();
                }
            }
        }

        Log.e("Analyzis","Finished");
    }

    public void openSuShell(){
        try{
            su = Runtime.getRuntime().exec("su");
            inputStream = new DataInputStream(su.getInputStream());
            outputStream = new DataOutputStream(su.getOutputStream());
        }catch(IOException e){
            System.out.println(e.getStackTrace());
        }
    }

    public void closeShell(){
        stopCapturing();
        su.destroy();
        su = null;
        inputStream = null;
        outputStream = null;
    }

    public void makeCopy(File file, String copy){
        try{
            FileInputStream in   = new FileInputStream(file);
            FileOutputStream out = new FileOutputStream("/sdcard/infpackets/" + copy);

            byte[] buffer = new byte[1024];
            int read;

            while( (read = in.read(buffer) ) != -1 ){
                out.write(buffer, 0, read);
            }

            in.close();
            in = null;

            out.flush();
            out.close();
            out = null;

        }catch(FileNotFoundException e){
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Runs TCPDump with root permission
     */
    public void startCapturing(){
        try{

        this.time = new Date();
        outputStream.writeBytes(this.binaryPath + " -G 10 tcp -w /sdcard/infpackets/capture.pcap\n");
        //Starts getting packets from shell
        //refreshRate.post(refreshOutput);
    }catch(IOException e){
        System.out.println(e.getStackTrace());
    }
}

    /**
     * Runs command in shell
     * @param command
     * @return
     */
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
        if ( runCommand("exit\n") ){

            try {
                outputStream.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // closeShell();

        //su = null;
        //refreshRate.removeCallbacks(refreshOutput);
        //inputStream = null;
        //outputStream = null;
        Log.e("Stop","Tcpdump stopped");
    }


    private Runnable refreshOutput = new Runnable() {
        @Override
        public void run() {
            try {
                if (inputStream.available() > 0) {
                    byte[] buffer = new byte[4096];

                    try {
                        inputStream.read(buffer, 0, 4096);

                        Log.e("Stream", new String(buffer));
                        Log.e("Buff", buffer[0] + "");
                    } catch (IOException e) {
                        stopCapturing();
                        return;
                    }
                }

            } catch (IOException e) {
                stopCapturing();
            }

            refreshRate.postDelayed(refreshOutput, 100);
        }
    };


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
