package com.secianus.burpxml;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/** Enforces a hard byte limit even if the file changes after its size check. */
final class LimitedInputStream extends FilterInputStream {
    private final long maximum;
    private long count;

    LimitedInputStream(InputStream input, long maximum) {
        super(input);
        this.maximum = maximum;
    }

    @Override
    public int read() throws IOException {
        int value = super.read();
        if (value != -1) {
            increment(1);
        }
        return value;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        int read = super.read(buffer, offset, length);
        if (read > 0) {
            increment(read);
        }
        return read;
    }

    private void increment(int amount) throws IOException {
        count += amount;
        if (count > maximum) {
            throw new IOException("XML file exceeds the " + maximum + " byte limit");
        }
    }
}
