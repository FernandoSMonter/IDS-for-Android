package com.infotool;

import android.content.Context;

import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Created by Fernando Sánchez on 16/04/2017.
 */

public class Tcpdump {

    final String binaryPath = "./data/local/tcpdump";
    Context context;
    Process su;

    DataOutputStream outputStream;

    public Tcpdump(Context context){
        this.context = context;
    }

    /**
     * Runs TCPDump with root permission
     */
    public void start(){
        try{
            su = Runtime.getRuntime().exec("su");
            outputStream = new DataOutputStream(su.getOutputStream());

            outputStream.writeBytes(this.binaryPath + " -w /sdcard/infpackages/packets.pcap\n");
            outputStream.flush();
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
    public void stop() {
        if ( runCommand("killall tcpdump") )
          closeShell();
    }


    public void closeShell(){
        su.destroy();
    }
}
