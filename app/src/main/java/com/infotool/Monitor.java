package com.infotool;


import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;

/**
 * Created by Fernando Sánchez on 12/05/2017.
 */

public class Monitor extends Thread {

    private final String path = "/sdcard/infpackets/";
    private final String capture_pcap = "capture.pcap";
    private final String analyze_pcap = "analyze.pcap";

    private boolean running;

    Date time;

    Tcpdump tcpdump;

    Analyzer analyzer;

    File capture;

    int copies;

    private int refreshRate = 10000;

    public Monitor(){

        clearFiles();

        //Prepares Tcpdump
        tcpdump = new Tcpdump();

        //Prepares Analyzer
        analyzer = new Analyzer();
    }

    public void clearFiles(){
        File file = new File(path + capture_pcap);

        if(file.exists()){
            file.delete();
        }

        file = new File(path + analyze_pcap);

        if( file.exists() ){
            file.delete();
        }

        file = null;
    }

    public boolean isRunning(){ return this.running; }

    @Override
    public void run() {
        running = true;

        //Opens the shell with root
        tcpdump.openSuShell();

        //Starts tcpdump
        tcpdump.startCapturing();

        time = new Date();

        while( running ){

           captureTraffic();

        }

        Log.e("Stopping","Run finished");
    }

    public void captureTraffic(){

            if( new Date().getTime() > time.getTime() + this.refreshRate ){
                //closeShell();

                capture = new File(this.path + this.capture_pcap);


                if( capture.exists() && capture.length() > 0){

                    tcpdump.stopCapturing();

                    makeCopy(capture, this.analyze_pcap);
                    Log.e("Copia", copies + "");


                    analyzer.analyze();
                    Log.e("Analyze","Analisis terminado");

                    capture.delete();

                    tcpdump.openSuShell();
                    tcpdump.startCapturing();

                    this.time = new Date();

                    this.copies++;


                }else{
                    //makeCopy(capture, "analyze.pcap");
                    Log.e("Captura", "Captura sin paquetes");
                    this.time = new Date();
                }

            }
    }

    public void kill(){

        if( tcpdump.isRunning() ){
            tcpdump.stopCapturing();
        }

        this.running = false;
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

}
