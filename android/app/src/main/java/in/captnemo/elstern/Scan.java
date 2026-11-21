package in.captnemo.elstern;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.SurfaceTexture;
import android.hardware.Camera;
import android.os.Bundle;
import android.view.Gravity;
import android.view.TextureView;
import android.widget.FrameLayout;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.ReaderException;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

@SuppressWarnings("deprecation")
public class Scan extends Activity implements TextureView.SurfaceTextureListener, Camera.PreviewCallback {
    Camera cam;
    Camera.Size ps;
    TextureView tv;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        tv = new TextureView(this);
        tv.setSurfaceTextureListener(this);
        FrameLayout f = new FrameLayout(this);
        f.addView(tv, new FrameLayout.LayoutParams(-1, -1, Gravity.CENTER));
        setContentView(f);
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{Manifest.permission.CAMERA}, 1);
    }

    @Override
    public void onRequestPermissionsResult(int rq, String[] p, int[] r) {
        recreate();
    }

    @Override
    public void onSurfaceTextureAvailable(SurfaceTexture st, int w, int h) {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return;
        try {
            cam = Camera.open();
            Camera.Parameters p = cam.getParameters();
            p.setFocusMode(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE);
            // best-matching preview size up to 720p; the view is resized to keep its aspect ratio
            float want = (float) h / w;
            for (Camera.Size c : p.getSupportedPreviewSizes())
                if (c.width <= 1280 && (ps == null || Math.abs(c.width / (float) c.height - want)
                        < Math.abs(ps.width / (float) ps.height - want))) ps = c;
            p.setPreviewSize(ps.width, ps.height);
            float ar = (float) ps.height / ps.width;
            boolean wide = w / (float) h > ar;
            tv.setLayoutParams(new FrameLayout.LayoutParams(wide ? (int) (h * ar) : w, wide ? h : (int) (w / ar), Gravity.CENTER));
            cam.setParameters(p);
            cam.setDisplayOrientation(90);
            cam.setPreviewTexture(st);
            cam.setPreviewCallback(this);
            cam.startPreview();
        } catch (Exception e) {
            finish();
        }
    }

    @Override
    public void onPreviewFrame(byte[] d, Camera c) {
        try {
            String t = new QRCodeReader().decode(new BinaryBitmap(new HybridBinarizer(
                    new PlanarYUVLuminanceSource(d, ps.width, ps.height, 0, 0, ps.width, ps.height, false)))).getText();
            setResult(RESULT_OK, new Intent().putExtra("t", t));
            finish();
        } catch (ReaderException e) {
            // no code in this frame
        }
    }

    @Override
    public boolean onSurfaceTextureDestroyed(SurfaceTexture st) {
        if (cam != null) {
            cam.setPreviewCallback(null);
            cam.release();
            cam = null;
        }
        return true;
    }

    @Override
    public void onSurfaceTextureSizeChanged(SurfaceTexture st, int w, int h) {
    }

    @Override
    public void onSurfaceTextureUpdated(SurfaceTexture st) {
    }
}
