package com.infotool;

import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;


public class MainActivity extends AppCompatActivity {
    /**
     * Tcpdump thread
     */
    Tcpdump tcpdump;
    Analyzer analyzer;
    Button beginButton, stopButton;

    protected void setViews(){
        beginButton = (Button) findViewById(R.id.begin_button);
        stopButton = (Button) findViewById(R.id.stop_button);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setViews();
        analyzer = new Analyzer(this);
    }

    /**
     *
     * @param v
     */
    public void startTcpdump(View v){
        //tcpdump = new Tcpdump(this);
        //tcpdump.start();
        //analyzer = new Analyzer(this);

        v.setVisibility(View.INVISIBLE);
        stopButton.setVisibility(View.VISIBLE);
    }

    /**
     *
     * @param v
     */
    public void stopTcpdump(View v){
        Toast.makeText(this, "Stopping tcpdump", Toast.LENGTH_SHORT).show();
        v.setVisibility(View.INVISIBLE);
        beginButton.setVisibility(View.VISIBLE);
    }

}

