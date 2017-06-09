package com.infotool;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    public Button startButton, stopButton;

    protected void setViews() {
        startButton = (Button) findViewById(R.id.begin_button);
        stopButton = (Button) findViewById(R.id.stop_button);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setViews();

        if(applicationInForeground()){
            startButton.setVisibility(View.INVISIBLE);
            stopButton.setVisibility(View.VISIBLE);
            // TODO  I Can get a service status from here with a new method to show the user whats going on in the service
            // TODO Obtener información como "Monitoreando red desde: fecha y hora" en la red "Nombre del SSID".
        }
    }


    /**
     * @param v
     */
    public void startTcpdump(View v) {
        Toast.makeText(this, R.string.starting_service, Toast.LENGTH_SHORT).show();
        v.setVisibility(View.INVISIBLE);
        stopButton.setVisibility(View.VISIBLE);

        Intent intent = new Intent(this, MainService.class);
        startService(intent);

    }

    /**
     * @param v
     */
    public void stopTcpdump(View v) {
        Toast.makeText(this, R.string.stopping_service, Toast.LENGTH_SHORT).show();
        v.setVisibility(View.INVISIBLE);
        startButton.setVisibility(View.VISIBLE);


        Intent intent = new Intent(this, MainService.class);
        stopService(intent);
    }


    public void startResponse(View v) {
        Intent intent = new Intent(this, ResponseActivity.class);
        startActivity(intent);
    }

    private boolean applicationInForeground() {
        return MainService.running;
    }

}

