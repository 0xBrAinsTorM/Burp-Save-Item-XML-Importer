package com.secianus.burpxml;

import java.util.Arrays;

/** Immutable, validated representation of one Burp XML item. */
public final class BurpItem {
    private final String host;
    private final int port;
    private final boolean secure;
    private final byte[] request;
    private final byte[] response;

    BurpItem(String host, int port, boolean secure, byte[] request, byte[] response) {
        this.host = host;
        this.port = port;
        this.secure = secure;
        this.request = Arrays.copyOf(request, request.length);
        this.response = response == null ? null : Arrays.copyOf(response, response.length);
    }

    public String host() {
        return host;
    }

    public int port() {
        return port;
    }

    public boolean secure() {
        return secure;
    }

    public byte[] request() {
        return Arrays.copyOf(request, request.length);
    }

    public boolean hasResponse() {
        return response != null;
    }

    public byte[] response() {
        return response == null ? null : Arrays.copyOf(response, response.length);
    }
}
