package com.runningwild.xault;

import android.content.Context;
import android.os.AsyncTask;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;

import go.Go;
import go.xault.Xault;


public class MakeId extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.make_id);
        Go.init(getApplicationContext());
        Button b = (Button) findViewById(R.id.makeIdButton);
        b.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                AsyncTask<Void, Void, Void> task = new AsyncTask<Void, Void, Void>() {
                    String errMsg;

                    @Override
                    protected void onPreExecute() {
                        EditText myEditText = (EditText) findViewById(R.id.makeIdName);
                        InputMethodManager imm = (InputMethodManager) getSystemService(
                                Context.INPUT_METHOD_SERVICE);
                        imm.hideSoftInputFromWindow(myEditText.getWindowToken(), 0);
                        ((ProgressBar) findViewById(R.id.makeIdProgress)).setVisibility(View.VISIBLE);
                    }

                    @Override
                    protected void onPostExecute(Void result) {
                        ((ProgressBar) findViewById(R.id.makeIdProgress)).setVisibility(View.INVISIBLE);
                        Toast.makeText(getApplicationContext(), "successfully generated keys", Toast.LENGTH_LONG).show();
                        finish();
                    }

                    @Override
                    protected Void doInBackground(Void... params) {
                        try {
                            Xault.MakeKeys("Buttons");
                            return null;
                        } catch (Exception e) {
                            errMsg = e.getMessage();
                            return null;
                        }
                    }
                };
                task.execute();
            }
        });
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_make_id, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }


}
