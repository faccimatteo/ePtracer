package com.eptracer.e2e;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/*
 * HTTP(S) GET through the platform stack: HttpURLConnection is OkHttp inside
 * the framework, its TLS is Conscrypt, i.e. BoringSSL in
 * /apex/com.android.conscrypt — the library every Android app ends up in.
 *
 * Runs two ways:
 *   app_process -cp e2e.dex /system/bin com.eptracer.e2e.E2EClient URL   (-p)
 *   am start -n com.eptracer.e2e/.E2EActivity --es url URL              (--package)
 *
 * The certificate is not verified: the suite is about where the plaintext can
 * be read, not about trust (the splice scenario proves the session is the
 * origin's own by the proxy edit reaching the client).
 */
public final class E2EClient {
    public static String fetch(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        if (c instanceof HttpsURLConnection) {
            TrustManager[] all = { new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] ch, String a) {}
                public void checkServerTrusted(X509Certificate[] ch, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            } };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, all, null);
            HttpsURLConnection h = (HttpsURLConnection) c;
            h.setSSLSocketFactory(ctx.getSocketFactory());
            h.setHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String host, javax.net.ssl.SSLSession s) { return true; }
            });
        }
        c.setConnectTimeout(10000);
        c.setReadTimeout(10000);
        StringBuilder out = new StringBuilder();
        out.append("HTTP ").append(c.getResponseCode()).append('\n');
        for (Map.Entry<String, List<String>> e : c.getHeaderFields().entrySet())
            if (e.getKey() != null)
                out.append(e.getKey()).append(": ").append(String.join(",", e.getValue())).append('\n');
        InputStream in = c.getInputStream();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        for (int n; (n = in.read(buf)) > 0; )
            body.write(buf, 0, n);
        out.append('\n').append(body.toString("UTF-8"));
        c.disconnect();
        return out.toString();
    }

    public static void main(String[] args) {
        try {
            System.out.print(fetch(args[0]));
            System.exit(0);
        } catch (Exception e) {
            System.err.println("E2E error: " + e);
            System.exit(1);
        }
    }
}
