package com.imom.crypto.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;

public class IOUtils {
	
	public static final Charset UTF8_CHARSET = Charset.forName("utf-8");
    public static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

    private IOUtils() {

    }
	
	public static byte[] readBytesFromStream(InputStream in) throws IOException {
        int i = in.available();
        if (i < DEFAULT_BUFFER_SIZE) {
            i = DEFAULT_BUFFER_SIZE;
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream(i);
        copy(in, bos);
        in.close();
        return bos.toByteArray();
    }
	
	public static int copy(final InputStream input, final OutputStream output) throws IOException {
	        return copy(input, output, DEFAULT_BUFFER_SIZE);
	}
	
	public static int copy(final InputStream input, final OutputStream output,
            int bufferSize) throws IOException {
        int avail = input.available();
        if (avail > 262144) {
            avail = 262144;
        }
        if (avail > bufferSize) {
            bufferSize = avail;
        }
        final byte[] buffer = new byte[bufferSize];
        int n = 0;
        n = input.read(buffer);
        int total = 0;
        while (-1 != n) {
            if (n == 0) {
                throw new IOException("0 bytes read in violation of InputStream.read(byte[])");
            }
            output.write(buffer, 0, n);
            total += n;
            n = input.read(buffer);
        }
        return total;
    }

}
