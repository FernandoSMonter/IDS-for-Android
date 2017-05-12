package com.infotool;

import android.provider.ContactsContract;
import android.util.Log;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by Fernando Sánchez on 25/04/2017.
 */

public class IpTables {
    DataInputStream inputStream;
    DataOutputStream outputStream;
    Process su;

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
        if( runCommand("exit\n") ){
            su.destroy();
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


    public void blockIp(String ip){
        if( runCommand("iptables -A INPUT -s " + ip + " -j DROP\n") ){
            Log.e("Iptables", "Dropping " + ip);
        }
    }

    public void resetRules(){
        if( runCommand("iptables -F\n") ){
            Log.e("Iptables","Iptables flushed");
        }
    }


}
