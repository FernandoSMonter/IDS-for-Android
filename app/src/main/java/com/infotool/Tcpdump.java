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
    /**
     * The path of arm tcpdump binary
     */
    final String binaryPath = "./data/local/tcpdump";

    /**
     * Main thread activity
     */
    Activity activity;

    /**
     * Su inputstream
     */
    DataInputStream inputStream;

    /**
     * Su outputstream
     */
    DataOutputStream outputStream;

    /**
     *
     */
    Handler refreshRate;

    /**
     * Su
     */
    Process su = null;

    Date time;

    boolean connection;

    public Tcpdump(Activity activity) {
       this.activity = activity;

      /*  boolean analyzing = true;

        while ( analyzing ){
            //Haciendo analisis
            if( new Date().getTime() > time.getTime() + 15000 ){
                // stopCapturing();

                capture = new File("/sdcard/infpackets/capture.pcap");

                //The capture has packets inside
                if( capture.exists() && capture.length() > 0 ){
                    //Executed once

                    Log.e("Time", "11 seconds elapsed, starting analysis module");
                    Log.e("Capture", "Capture size: " + capture.length());

                    //makeCopy(capture, "analyze.pcap");

                    Log.e("Analyze","Analyze.pcap replaced");
                    *//*if( runCommand("cp /sdcard/infpackets/capture.pcap /sdcard/infpackets/analyze.pcap\n") )
                        Log.e("Copied","File copied");
                    else
                        Log.e("Copied", "Error copying file");*//*

                    //new Analyzer(activity, new Date().getTime()).start();
                    analyzing = false;
                    //closeShell();

                }else{
                    Log.e("Packet","Capture size: " + capture.length());
                    // startCapturing();
                    //No packet captured, wait for next capture update time

                }
                startCapturing();
                Log.e("Refresh", "Refreshing pcap");
            }
        }

        Log.e("Analyzis","Finished");*/
    }

    @Override
    public void run(){
        File capture;
        int copies = 0;
        boolean activated = false;
        this.connection = true;
        Analyzer analyze = new Analyzer(this.activity);
        showToast("Empezando captura");

        //Opens the shell with root
        this.openSuShell();

        //Starts tcpdump
        this.startCapturing();

        while( this.connection ){

            if( new Date().getTime() > time.getTime() + 10000){
              //closeShell();

                capture = new File("/sdcard/infpackets/capture.pcap");


                if( capture.exists() && capture.length() > 0){
                    this.closeShell();
                    killAll("./data/local/tcpdump");
                    makeCopy(capture, "analyze.pcap");
                    Log.e("Copia", copies + "");


                    analyze.analyze();

                    Log.e("Analyze","Analisis terminado");
                    capture.delete();

                    this.openSuShell();
                    this.startCapturing();
                    this.time = new Date();

                    copies++;

                }else{
                    //makeCopy(capture, "analyze.pcap");
                    Log.e("Captura", "Captura sin paquetes");
                    this.time = new Date();
                }

            }

        }
    }

    public void openSuShell(){
        try{
            this.su = Runtime.getRuntime().exec("su");
            this.inputStream = new DataInputStream(su.getInputStream());
            this.outputStream = new DataOutputStream(su.getOutputStream());

        }catch(IOException e){
            System.out.println(e.getStackTrace());
        }
    }

    public void closeShell(){
        //stopCapturing();

        this.su.destroy();
        this.su = null;

        this.inputStream = null;
        this.outputStream = null;
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
        outputStream.writeBytes(this.binaryPath + " tcp -w /sdcard/infpackets/capture.pcap\n");
            Log.e("Capture","Capturando...");
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

    /**
     * Android killall pseudo-command (within rooted env)
     * @param
     */
    private void killAll(String name){
        try {
            Runtime.getRuntime().exec("su");

            Process p = Runtime.getRuntime().exec("ps "+ name);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
            String line = null;
            int i=0;
            while ((line = in.readLine()) != null) {
                if(i>0)//ignore title
                    Runtime.getRuntime().exec("kill " + line.replaceAll(" {2,}", " ").split(" ")[1]);
                i+=1;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
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
