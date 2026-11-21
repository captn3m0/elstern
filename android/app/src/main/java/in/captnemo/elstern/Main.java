package in.captnemo.elstern;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Insets;
import android.hardware.biometrics.BiometricManager.Authenticators;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.concurrent.Callable;
import java.util.function.BiConsumer;

public class Main extends Activity {
    static final String IDLE = "Enroll / log in";

    EditText link;
    Button go;
    TextView out;
    Elster session;
    // bumped on every edit, so results for an older link are dropped
    int generation;
    String lastUsed = "";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        link = new EditText(this);
        link.setHint("elster-secure://sec?p=...");
        link.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable e) {
                check(e.toString().trim());
            }
        });
        Button scan = new Button(this);
        scan.setText("Scan QR");
        scan.setOnClickListener(v -> startActivityForResult(new Intent(this, Scan.class), 1));
        go = new Button(this);
        go.setText(IDLE);
        go.setEnabled(false);
        go.setOnClickListener(v -> confirm());
        out = new TextView(this);
        out.setTextIsSelectable(true);

        int margin = dp(16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setOnApplyWindowInsetsListener((v, w) -> {
            Insets i = w.getInsets(WindowInsets.Type.systemBars());
            v.setPadding(i.left + margin, i.top + margin, i.right + margin, i.bottom + margin);
            return w;
        });
        root.addView(link);
        for (View v : new View[]{scan, go, out}) {
            LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2);
            p.topMargin = margin;
            root.addView(v, p);
        }
        setContentView(root);
        link.setText(getIntent().getDataString());
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (result == RESULT_OK) link.setText(data.getStringExtra(Scan.TEXT));
    }

    @Override
    public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (!focused || link.getText().length() > 0) return;
        ClipData clip = getSystemService(ClipboardManager.class).getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0 || clip.getItemAt(0).getText() == null) return;
        String text = clip.getItemAt(0).getText().toString().trim();
        if (Link.parse(text) != null && !text.equals(lastUsed)) link.setText(text);
    }

    void check(String uri) {
        int g = ++generation;
        session = null;
        go.setEnabled(false);
        go.setText(IDLE);
        Link l = Link.parse(uri);
        if (l == null) return;
        go.setText("Checking...");
        background(() -> new Elster(l, Device.load(this)), (s, err) -> {
            if (g != generation) return;
            if (err != null) {
                go.setText(IDLE);
                out.setText(err.toString());
                return;
            }
            session = s;
            out.setText(describe(s));
            go.setText(s.enrolling() ? "Enroll" : "Log in");
            go.setEnabled(true);
        });
    }

    void confirm() {
        Elster s = session;
        String uri = link.getText().toString().trim();
        go.setEnabled(false);
        Runnable run = () -> {
            out.setText("...");
            background(s::confirm, (result, err) -> {
                lastUsed = uri;
                link.setText("");
                out.setText(err != null ? err.toString() : result);
            });
        };
        if (Device.hasScreenLock(this)) unlock(run);
        else run.run();
    }

    void unlock(Runnable then) {
        int g = generation;
        new BiometricPrompt.Builder(this).setTitle(go.getText())
                .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG | Authenticators.DEVICE_CREDENTIAL)
                .build()
                .authenticate(new CancellationSignal(), getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                        then.run();
                    }

                    @Override
                    public void onAuthenticationError(int code, CharSequence message) {
                        out.setText(message);
                        if (g == generation) go.setEnabled(true);
                    }
                });
    }

    static String describe(Elster s) {
        StringBuilder sb = new StringBuilder();
        for (String[] f : new String[][]{{"benutzername", "Account"}, {"email", "Email"}}) {
            String v = s.field(f[0], "");
            if (!v.isEmpty()) sb.append(f[1]).append(": ").append(v).append('\n');
        }
        if (s.enrolling()) sb.append("Device: ").append(Build.MODEL);
        return sb.toString().trim();
    }

    <T> void background(Callable<T> work, BiConsumer<T, Exception> done) {
        new Thread(() -> {
            T result = null;
            Exception error = null;
            try {
                result = work.call();
            } catch (Exception e) {
                error = e;
            }
            T r = result;
            Exception e = error;
            runOnUiThread(() -> done.accept(r, e));
        }).start();
    }

    int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }
}
