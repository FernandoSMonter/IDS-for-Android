package com.infotool;

import android.content.Intent;
import android.net.wifi.WifiManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class ResponseActivity extends AppCompatActivity {

    Bundle information;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_response);

        TextView attackerIp   = (TextView) findViewById(R.id.attacker_ip);
        //TextView attackerPort = (TextView) findViewById(R.id.attacker_port);

        this.information = getIntent().getExtras();

        attackerIp.setText(this.information.getString("ip"));
        //attackerPort.setText(this.information.getString("port"));
    }

    public void blockConnection(View v){
        IpTables iptables = new IpTables();


        iptables.blockIp( this.information.getString("ip") );

        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
    }

    public void killConnection(View v){
        WifiManager wifi = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
        wifi.disconnect();

        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
    }
}
