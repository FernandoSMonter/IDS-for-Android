package com.infotool;


import android.Manifest;
import android.app.Activity;
import android.os.AsyncTask;
import android.os.Environment;
import android.support.v4.app.ActivityCompat;
import android.util.Log;
import android.widget.Toast;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;

public class Analyzer{

    Pcap pcap;
    StringBuilder buffer;
    Activity activity;

    final String pcap_path =  "/sdcard/Download/connection.pcap";//"/sdcard/infpackets/packets.pcap";

    boolean treat_string;

    public Analyzer(Activity activity){
        pcap = null;
        buffer = new StringBuilder();

        this.activity = activity;
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
        }else showToast("Pcap abierto con éxito");
    }


    private void mainAnalysis(){
        int threat_packet_counter = 0;
        int packets_to_read = 100;
        boolean threatDetected = false;

        PcapHeader pcapHeader = new PcapHeader();

        JBuffer jbuffer = new JBuffer(JMemory.POINTER);

        for (int i = 0; i < packets_to_read; i++){
            Log.e("Paquete " ,"Paquete: " + (i + 1));
            pcap.nextEx(pcapHeader, jbuffer);

            //Gets tcpHeader bytes, always starting from the 35th byte
            //TCP size = 32 bytes

            byte [] tcpHeader = jbuffer.getByteArray(34, 32);
            //Find the SYN-ACK packet
            if( flagsSynAck(tcpHeader) ){
                //checkOptionsField(tcpHeader);
                //Starts 2nd phase

                //Only checks tcps with ACK, looks for pattern
                for (int j = 0; j < packets_to_read; j++){
                    pcap.nextEx(pcapHeader, jbuffer);
                    byte [] tcpAckHeader = jbuffer.getByteArray(34, 32);

                    if( flagsPshAck(tcpAckHeader) && checkHeaderLength(1514, pcapHeader)){
                        findString(jbuffer);
                        threat_packet_counter++;
                    }

                    if( threat_packet_counter == 10){
                        Log.e("Pattern", "Founded pattern for meterpreter attack");
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
     * @param pcap
     * @return
     */
    private boolean flagsSynAck(byte[] tcpHeader){
        //                       FLAGS
        //                    U A P R S F
        //SYN y ACK = 18 = 00 0 1 0 0 1 0
        if( tcpHeader[13] == 18 ){
            Log.e("Flags", tcpHeader[13] + "");
            return true;
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
            Log.e("Finding ", "Meterpreter string founded.");
            return true;
        }

        return false;
    }
}
