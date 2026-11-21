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
    static final String TEXT = "t";

    Camera camera;
    Camera.Size size;
    TextureView preview;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        preview = new TextureView(this);
        preview.setSurfaceTextureListener(this);
        FrameLayout frame = new FrameLayout(this);
        frame.addView(preview, new FrameLayout.LayoutParams(-1, -1, Gravity.CENTER));
        setContentView(frame);
        if (!hasCamera()) requestPermissions(new String[]{Manifest.permission.CAMERA}, 1);
    }

    @Override
    public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        recreate();
    }

    boolean hasCamera() {
        return checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED;
    }

    @Override
    public void onSurfaceTextureAvailable(SurfaceTexture st, int w, int h) {
        if (!hasCamera()) return;
        try {
            camera = Camera.open();
            Camera.Parameters p = camera.getParameters();
            p.setFocusMode(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE);
            size = closestSize(p, (float) h / w);
            p.setPreviewSize(size.width, size.height);
            camera.setParameters(p);
            fitPreview(w, h);
            camera.setDisplayOrientation(90);
            camera.setPreviewTexture(st);
            camera.setPreviewCallback(this);
            camera.startPreview();
        } catch (Exception e) {
            finish();
        }
    }

    static Camera.Size closestSize(Camera.Parameters p, float ratio) {
        Camera.Size best = null;
        for (Camera.Size s : p.getSupportedPreviewSizes()) {
            if (s.width <= 1280 && (best == null || distance(s, ratio) < distance(best, ratio))) best = s;
        }
        return best;
    }

    static float distance(Camera.Size s, float ratio) {
        return Math.abs(s.width / (float) s.height - ratio);
    }

    void fitPreview(int w, int h) {
        float ratio = (float) size.height / size.width;
        boolean wide = w / (float) h > ratio;
        int width = wide ? (int) (h * ratio) : w, height = wide ? h : (int) (w / ratio);
        preview.setLayoutParams(new FrameLayout.LayoutParams(width, height, Gravity.CENTER));
    }

    @Override
    public void onPreviewFrame(byte[] data, Camera c) {
        PlanarYUVLuminanceSource frame = new PlanarYUVLuminanceSource(
                data, size.width, size.height, 0, 0, size.width, size.height, false);
        try {
            String text = new QRCodeReader().decode(new BinaryBitmap(new HybridBinarizer(frame))).getText();
            setResult(RESULT_OK, new Intent().putExtra(TEXT, text));
            finish();
        } catch (ReaderException e) {
            // no QR code in this frame
        }
    }

    @Override
    public boolean onSurfaceTextureDestroyed(SurfaceTexture st) {
        if (camera != null) {
            camera.setPreviewCallback(null);
            camera.release();
            camera = null;
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
