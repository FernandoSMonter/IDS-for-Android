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

public class Tcpdump{
    /**
     * The path of arm tcpdump binary
     */
    final String binaryPath = "./data/local/tcpdump";

    private  boolean running = false;

    /**
     * Su inputstream
     */
    DataInputStream inputStream;

    /**
     * Su outputstream
     */
    DataOutputStream outputStream;


    /**
     * Su
     */
    Process su = null;


    public Tcpdump() {


    }

   /* @Override
    public void run(){
        File capture;
        int copies = 0;
        boolean activated = false;
        this.connection = true;
        Analyzer analyze = new Analyzer(this.activity);

        //Opens the shell with root
        this.openSuShell();

        //Starts tcpdump
        this.startCapturing();

        while( this.connection ){

            if( new Date().getTime() > time.getTime() + 10000){
              //closeShell();

                capture = new File("/sdcard/infpackets/capture.pcap");


                if( capture.exists() && capture.length() > 0){
                    this.stopCapturing();
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
    }*/

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

    /**
     * Runs TCPDump with root permission
     */
    public void startCapturing(){
        try{
        outputStream.writeBytes(this.binaryPath + " tcp -w /sdcard/infpackets/capture.pcap\n");
            this.running = true;
            Log.e("Capture","Tcpdump iniciado");
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
        try{

            this.closeShell();
            this.running = false;

        }catch(NullPointerException e){
            Log.e("Closed", "Already closed");
        }

        killAll("./data/local/tcpdump");
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

    public boolean isRunning(){
        return this.running;
    }
}
