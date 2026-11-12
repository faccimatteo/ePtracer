package com.eptracer.e2e;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

/* Fetches the `url` extra off the main thread, logs the outcome as
 * "E2E OK <first line>" / "E2E FAIL <error>" under the tag ePtracerE2E, done. */
public final class E2EActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        final String url = getIntent().getStringExtra("url");
        new Thread(new Runnable() {
            public void run() {
                try {
                    String r = E2EClient.fetch(url);
                    Log.i("ePtracerE2E", "E2E OK " + r.replace('\n', '|'));
                } catch (Exception e) {
                    Log.i("ePtracerE2E", "E2E FAIL " + e);
                }
                finish();
            }
        }).start();
    }
}
