package com.infotool;

import android.app.Activity;
import android.os.Environment;
import android.os.SystemClock;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.format.FormatUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

public class Analyzer{

    /**
     *
     */
    Pcap pcap;

    /**
     *
     */
    StringBuilder buffer;

    /**
     *
     */
    Activity activity;

    /**
     *
     */
    Date then;

    /**
     *
     */
    final String pcap_path = "/sdcard/infpackets/analyze.pcap";

    /**
     *
     */
    final String capture_path = "/sdcard/infpackets/capture.pcap";

    /**
     *
     */
    boolean treat_string;

    boolean threatDetected;

    /**
     *
     */
    int opening_counter;

    public String attackerSYNIP;
    public String attackerSYNPort;

    public String attackerIP;
    public String attackerPort;

    public Analyzer(){
        pcap   = null;
        buffer = new StringBuilder();
        opening_counter = 0;

        //Time in milliseconds
        this.then = new Date();
    }

   public void analyze(){
       File analyze = new File(pcap_path);

       if( this.openPcapFile() ){
               this.mainAnalysis();
                analyze.delete();
       }else {
           Log.e("Error","No file, monitor");
       }
   }

   public boolean isThreatDetected(){
       return this.threatDetected;
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


    /**
     * Opens offline packet
     * @return
     */
    private boolean openPcapFile(){
        boolean readed = false;

        File analysis = new File(pcap_path);

        if(!isExternalStorageReadable()){
            Log.e("Perm","Sin permisos w/r");
        }

        if(analysis.exists() && analysis.length() > 0){
            pcap = Pcap.openOffline(pcap_path, buffer);

            if (pcap == null) {
                Log.e("Error: ","" + buffer);
                return false;
            }else {
                Log.e("Abiertos", opening_counter++ + "");
                return true;
            }
        }
        return false;
    }

    /**
     * Runs main analysis
     */
    private void mainAnalysis(){
        long init = System.currentTimeMillis();

        boolean analyzing = true;

        int packet_umbral = 30;

        int threat_packet_counter = 0;
        int packet_counter = 0;

        byte []tcpHeader;
        byte [] ipHeader;
        threatDetected = false;

        PcapHeader pcapHeader = new PcapHeader();

        JBuffer jbuffer = new JBuffer(JMemory.POINTER);

       while ( pcap.nextEx(pcapHeader, jbuffer) == Pcap.NEXT_EX_OK ){

            Log.e("Paquete " , "" + (++packet_counter));

            //Gets tcpHeader bytes, always starting from the 35th byte
            //TCP size = 32 bytes
           if( jbuffer.size() >= 66 ){
               tcpHeader = jbuffer.getByteArray(34, 32);
           }else
               continue;

           if( jbuffer.size() >= 33 ){
               ipHeader  =  jbuffer.getByteArray(14, 20);
               attackerIP   = getSourceIP(ipHeader);
               attackerPort = getSourcePort(tcpHeader);
           }else
               continue;

            //Find the SYN-ACK packet
            if( flagsSynAck(tcpHeader) ){
                //checkOptionsField(tcpHeader);
                //Get possible attacker Socket
                if( jbuffer.size() >= 33 ){
                    ipHeader  =  jbuffer.getByteArray(14, 20);
                    attackerSYNIP   = getSourceIP(ipHeader);
                    attackerSYNPort = getSourcePort(tcpHeader);
                }else
                    continue;

                //Starts 2nd phase
                //Only checks tcps with ACK, looks for pattern
                while ( pcap.nextEx(pcapHeader, jbuffer) == Pcap.NEXT_EX_OK ){
                    Log.e("Paquete ", "" + (++packet_counter));

                    if( jbuffer.size() >= 66 ){
                        tcpHeader = jbuffer.getByteArray(34, 32);
                    }else
                        continue;

                    if( flagsPshAck(tcpHeader) && checkHeaderLength(1514, pcapHeader)){
                        //getIP(ipAckHeader);
                        findString(jbuffer);        //Looks for suspicious strings in packet
                        threat_packet_counter++;    //Counts strange packet

                        //IP size = 20 bytes
                        if( jbuffer.size() >= 33 ){
                            ipHeader  =  jbuffer.getByteArray(14, 20);
                            attackerIP   = getSourceIP(ipHeader);
                            attackerPort = getSourcePort(tcpHeader);
                        }else
                            continue;
                    }

                    if( threat_packet_counter >= 10){
                        Log.e("Pattern", "Ataque por Meterpreter detectado.");
                        Log.e("Paquetes", "Paquetes analizados: " + packet_counter);
                        Log.e("Socket", "En SYN/ACK " + attackerSYNIP + ":" + attackerSYNPort);
                        Log.e("Attack", "En ataque " + attackerIP + ":" + attackerPort);
                        this.threatDetected = true;
                        makeCopy(new File(pcap_path), "threat" + System.currentTimeMillis() + ".pcap");
                        break;
                    }else if( packet_counter >= packet_umbral ){
                        break;
                    }
                }
            }
           if(threatDetected)  break;
        }

        long finish = System.currentTimeMillis();
        Log.e("Analizado","Tiempo en analizar " + packet_counter + " paquetes: " + ( finish - init ) + "ms.");
    }

    /**
     * Verificacion de SYN ACK de paquetes
     * @param
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
        if(  header.caplen() >= max ){
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
        Log.e("IP", "Source: " + (ipHeader[12] & 0xFF) + "." + (ipHeader[13] & 0xFF) + "." + (ipHeader[14] & 0xFF) + "." + (ipHeader[15] & 0xFF));
    }

    private String getSourceIP(byte [] ipHeader){
        return (ipHeader[12] & 0xFF) + "." + (ipHeader[13] & 0xFF) + "." + (ipHeader[14] & 0xFF) + "." + (ipHeader[15] & 0xFF);
    }

    private String getSourcePort(byte [] tcpHeader){
        return (tcpHeader[0] & 0xFF) + (tcpHeader[1] & 0xFF) + "";
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
