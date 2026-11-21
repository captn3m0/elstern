package in.captnemo.elstern;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.SurfaceTexture;
import android.hardware.Camera;
import android.os.Bundle;
import android.view.TextureView;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.ReaderException;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

@SuppressWarnings("deprecation")
public class Scan extends Activity implements TextureView.SurfaceTextureListener, Camera.PreviewCallback {
    Camera cam;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextureView tv = new TextureView(this);
        tv.setSurfaceTextureListener(this);
        setContentView(tv);
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
        Camera.Size s = c.getParameters().getPreviewSize();
        try {
            String t = new QRCodeReader().decode(new BinaryBitmap(new HybridBinarizer(
                    new PlanarYUVLuminanceSource(d, s.width, s.height, 0, 0, s.width, s.height, false)))).getText();
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
