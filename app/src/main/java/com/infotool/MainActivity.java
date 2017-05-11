package com.infotool;

import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;


public class MainActivity extends AppCompatActivity {
    /**
     * Tcpdump thread
     */
    Capturer capturer;
    Tcpdump tcpdump;
    Analyzer analyzer;
    Diagnostic diagnostic;

    public Button beginButton, stopButton;
    public TextView notification;

    protected void setViews(){
        beginButton  = (Button) findViewById(R.id.begin_button);
        stopButton   = (Button) findViewById(R.id.stop_button);
        notification = (TextView) findViewById(R.id.notification);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setViews();
        //analyzer = new Analyzer(this);
    }

    /**
     *
     * @param v
     */
    public void startTcpdump(View v){
        v.setVisibility(View.INVISIBLE);
        stopButton.setVisibility(View.VISIBLE);

        //Monitoring module thread
        tcpdump = new Tcpdump(this);
        tcpdump.start();

    }

    /**
     *
     * @param v
     */
    public void stopTcpdump(View v){
        Toast.makeText(this, "Stopping tcpdump", Toast.LENGTH_SHORT).show();
        tcpdump.kill();
        v.setVisibility(View.INVISIBLE);
        beginButton.setVisibility(View.VISIBLE);
    }

}

