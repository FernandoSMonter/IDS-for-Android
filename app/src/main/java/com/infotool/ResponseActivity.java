package com.infotool;

import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import org.w3c.dom.Text;

public class ResponseActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_response);

        TextView attackerIp   = (TextView) findViewById(R.id.attacker_ip);
        TextView attackerPort = (TextView) findViewById(R.id.attacker_port);

        Bundle information = getIntent().getExtras();

        attackerIp.setText(information.getString("ip"));
        attackerPort.setText(information.getString("port"));
    }


    public void blockConnection(){

    }

    public void killConnection(){

    }
}
