package com.infotool;

import android.app.Activity;
import android.os.Environment;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;

import java.util.Date;

public class Analyzer extends Thread{

    Pcap pcap;
    StringBuilder buffer;
    Activity activity;

    long then;

    final String pcap_path = "/sdcard/Download/connection.pcap";

    boolean treat_string;

    int opening_counter;

    public Analyzer(Activity activity){
        pcap   = null;
        buffer = new StringBuilder();
        opening_counter = 0;

        //time in seconds sin Epoch
        this.then = then / 1000;

        this.activity = activity;

    }

   @Override
   public void run(){

       this.openPcapFile();
       this.mainAnalysis();
   }

    /* Checks if external storage is available to at least read */
    public boolean isExternalStorageReadable() {
        String state = Environment.getExternalStorageState();
        if (Environment.MEDIA_MOUNTED.equals(state) ||
                Environment.MEDIA_MOUNTED_READ_ONLY.equals(state)) {
            return true;
        }
        return false;
    }

    public void showNotification(final String message){
        this.activity.runOnUiThread(new Runnable(){
            @Override
            public void run() {
                TextView notify = (TextView)activity.findViewById(R.id.notification);
                notify.setText(message);
            }
        });
    }

    public void showToast(String message){
        final String msg = message;
        this.activity.runOnUiThread(new Runnable(){
            @Override
            public void run() {
                Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
            }
        });
    }

    //androidpayload.stage.Meterpreter

    /**
     * Opens offline packet
     * @return
     */
    private void openPcapFile(){
        if(!isExternalStorageReadable()){
            showToast("Sin permisos w/r");
        }

        pcap = Pcap.openOffline(pcap_path, buffer);

        if (pcap == null) {
            showToast("Error: " + buffer);
        }else {
            showToast("Pcap abierto con éxito: " + this.opening_counter++);
        }
    }

    /**
     * Runs main analysis
     */
    private void mainAnalysis(){

        int threat_packet_counter = 0;
        int packets_to_read = 100;
        boolean threatDetected = false;

        PcapHeader pcapHeader = new PcapHeader();

        JBuffer jbuffer = new JBuffer(JMemory.POINTER);

        for (int i = 0; i < packets_to_read; i++){
            Log.e("Paquete " , "" + (i + 1));
            pcap.nextEx(pcapHeader, jbuffer);

            //Gets tcpHeader bytes, always starting from the 35th byte
            //TCP size = 32 bytes
            byte [] tcpHeader = jbuffer.getByteArray(34, 32);

            //IP size = 20 bytes
            byte [] ipHeader  =  jbuffer.getByteArray(15, 20);

            //Find the SYN-ACK packet
            if( flagsSynAck(tcpHeader) ){
                //checkOptionsField(tcpHeader);
                //Starts 2nd phase

                //Only checks tcps with ACK, looks for pattern
                for (int j = i + 1; j < packets_to_read; j++){
                    Log.e("Paquete ", "" + (j + 1));
                    pcap.nextEx(pcapHeader, jbuffer);

                    //IP size = 20 bytes
                    byte [] ipAckHeader  =  jbuffer.getByteArray(14, 33);

                    byte [] tcpAckHeader = jbuffer.getByteArray(34, 32);

                    if( flagsPshAck(tcpAckHeader) && checkHeaderLength(1514, pcapHeader)){
                        //getIP(ipAckHeader);
                        findString(jbuffer);        //Looks for suspicious strings in packet
                        threat_packet_counter++;    //Counts strange packet
                    }

                    if( threat_packet_counter >= 10){
                        Log.e("Pattern", "Ataque por Meterpreter detectado.");
                        Log.e("Paquetes", "Paquetes analizados: " + (j + i +1));
                        showNotification("Ataque por Meterpreter detectado.\nPaquetes analizados: " + (j + i + 1) +
                                         "\nIP y Puerto atacante" );
                        threatDetected = true;
                        break;
                    }
                }
            }
            if(threatDetected)
                break;
        }
    }

    /**
     * Verificacion de SYN ACK de paquetes
     * @param byte
     * @return boolean
     */
    private boolean flagsSynAck(byte[] tcpHeader){
        //                       FLAGS
        //                    U A P R S F
        //SYN y ACK = 18 = 00 0 1 0 0 1 0
        if( tcpHeader[13] == 18 ){
            Log.e("Flags", "Found SYN/ACK " + tcpHeader[13] + "");
            return true;
        }
        return false;
    }

    private boolean flagsPshAck(byte[] tcpHeader){
        //                       FLAGS
        //                    U A P R S F
        //PSH y ACK = 18 = 00 0 1 1 0 0 0 = 24
        //ACK                 0 1 0 0 0 0 = 16

        if( tcpHeader[13] == 16 ){
            Log.e("Has Ack", tcpHeader[13] + "");
            return true;
        }else if( tcpHeader[13] == 24 ){
            Log.e("Has [psh, Ack]", tcpHeader[13] + "");
        }

        return false;
    }

    private boolean checkWindowSize(JBuffer packet, int min_size){
       // Log.e("Byte 35", Integer.toBinaryString(Integer.parseInt(packet.getByte(48) + "")));
        return true;
    }

    private boolean checkOptionsField(byte[] tcpHeader){
        //Options starts in byte 21
        //Maximum segment size: 0101 1011 0100‬ == 1460
        Log.e("Window size", tcpHeader[23] + "");

        if(  tcpHeader[22] + tcpHeader[23] == 1460 ){
            Log.e("Window size", tcpHeader[22] + tcpHeader[23] + "");
            return true;
        }

        return false;
    }

    private boolean checkHeaderLength(int max, PcapHeader header){
        if( max == header.caplen() ){
            Log.e("TAM: ", header.caplen() + "");
            return true;
        }
        return false;
    }

    private boolean findString(JBuffer packet){
        StringBuilder str = new StringBuilder();

        packet.getUTF8String(0, str, packet.size());
        String rawString = str.toString();

        if( rawString.contains("Meterpreter") ){
            Log.e("Finding ", "Meterpreter string found.");
            return true;
        }

        return false;
    }

    private void getIP(byte[] ipHeader){
        String src_ip, dst_ip;

        Log.e("IP", "Source: " + ipHeader[11]);
        Log.e("IP", "Destination: " + ipHeader[15] + "." + ipHeader[16] + "." + ipHeader[17] + "." + ipHeader[18]);
    }
}
