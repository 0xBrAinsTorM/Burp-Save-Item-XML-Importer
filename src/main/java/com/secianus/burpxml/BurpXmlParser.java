package com.secianus.burpxml;

import java.io.IOException;
import java.io.InputStream;
import java.net.IDN;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/** Streaming, fail-closed parser for Burp Suite Save item(s) XML exports. */
public final class BurpXmlParser {
    public static final long MAX_FILE_BYTES = 50L * 1024 * 1024;
    public static final int MAX_ITEMS = 10_000;
    public static final int MAX_REQUEST_BYTES = 10 * 1024 * 1024;
    public static final int MAX_RESPONSE_BYTES = 30 * 1024 * 1024;

    private static final int MAX_SMALL_FIELD_CHARS = 4096;
    private static final int MAX_DTD_CHARS = 256 * 1024;

    public List<BurpItem> parse(Path path) throws ImportException {
        validatePath(path);
        XMLInputFactory factory = secureFactory();

        try (InputStream raw = Files.newInputStream(path);
             InputStream limited = new LimitedInputStream(raw, MAX_FILE_BYTES)) {
            XMLStreamReader reader = factory.createXMLStreamReader(limited);
            try {
                return readDocument(reader);
            } finally {
                reader.close();
            }
        } catch (IOException | XMLStreamException e) {
            throw new ImportException("Could not parse XML: " + safeMessage(e), e);
        }
    }

    private static void validatePath(Path path) throws ImportException {
        try {
            if (path == null || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new ImportException("Select a regular XML file (symbolic links are not accepted)");
            }
            long size = Files.size(path);
            if (size == 0) {
                throw new ImportException("The selected XML file is empty");
            }
            if (size > MAX_FILE_BYTES) {
                throw new ImportException("XML file exceeds the 50 MiB limit");
            }
        } catch (IOException e) {
            throw new ImportException("Could not inspect selected file: " + safeMessage(e), e);
        }
    }

    private static XMLInputFactory secureFactory() throws ImportException {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        requireProperty(factory, XMLInputFactory.SUPPORT_DTD, false);
        requireProperty(factory, "javax.xml.stream.isSupportingExternalEntities", false);
        requireProperty(factory, XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
        factory.setXMLResolver((publicId, systemId, baseUri, namespace) -> {
            throw new XMLStreamException("External XML resources are forbidden");
        });
        return factory;
    }

    private static void requireProperty(XMLInputFactory factory, String property, Object value)
            throws ImportException {
        try {
            factory.setProperty(property, value);
            Object actual = factory.getProperty(property);
            if (!value.equals(actual)) {
                throw new ImportException("XML parser cannot enforce security property: " + property);
            }
        } catch (IllegalArgumentException e) {
            throw new ImportException("XML parser does not support required security property: " + property, e);
        }
    }

    private static List<BurpItem> readDocument(XMLStreamReader reader)
            throws XMLStreamException, ImportException {
        List<BurpItem> items = new ArrayList<>();
        boolean rootSeen = false;
        boolean rootClosed = false;

        while (reader.hasNext()) {
            int event = reader.next();
            rejectDangerousEvent(reader, event);
            if (event == XMLStreamConstants.START_ELEMENT) {
                rejectNamespace(reader);
                if (!rootSeen) {
                    if (!"items".equals(reader.getLocalName())) {
                        throw new ImportException("Expected Burp XML root element <items>");
                    }
                    rootSeen = true;
                } else if (!rootClosed && "item".equals(reader.getLocalName())) {
                    if (items.size() >= MAX_ITEMS) {
                        throw new ImportException("XML contains more than " + MAX_ITEMS + " items");
                    }
                    items.add(readItem(reader, items.size() + 1));
                } else {
                    throw new ImportException("Unexpected element <" + reader.getLocalName() + "> outside <item>");
                }
            } else if (event == XMLStreamConstants.END_ELEMENT && rootSeen
                    && "items".equals(reader.getLocalName())) {
                rootClosed = true;
            } else if (event == XMLStreamConstants.CHARACTERS && rootSeen
                    && !reader.isWhiteSpace()) {
                throw new ImportException("Unexpected text outside <item>");
            }
        }

        if (!rootSeen || !rootClosed) {
            throw new ImportException("Incomplete Burp XML document");
        }
        if (items.isEmpty()) {
            throw new ImportException("Burp XML contains no <item> entries");
        }
        return List.copyOf(items);
    }

    private static BurpItem readItem(XMLStreamReader reader, int index)
            throws XMLStreamException, ImportException {
        String host = null;
        String protocol = null;
        String portText = null;
        String requestText = null;
        String responseText = null;
        boolean requestBase64 = false;
        boolean responseBase64 = false;

        while (reader.hasNext()) {
            int event = reader.next();
            rejectDangerousEvent(reader, event);
            if (event == XMLStreamConstants.START_ELEMENT) {
                rejectNamespace(reader);
                String name = reader.getLocalName();
                switch (name) {
                    case "host":
                        host = unique(host, readText(reader, MAX_SMALL_FIELD_CHARS), name, index);
                        break;
                    case "port":
                        portText = unique(portText, readText(reader, MAX_SMALL_FIELD_CHARS), name, index);
                        break;
                    case "protocol":
                        protocol = unique(protocol, readText(reader, MAX_SMALL_FIELD_CHARS), name, index);
                        break;
                    case "request":
                        if (requestText != null) {
                            throw duplicate(name, index);
                        }
                        requestBase64 = hasTrueBase64Attribute(reader, name, index);
                        requestText = readText(reader, maxBase64Characters(MAX_REQUEST_BYTES));
                        break;
                    case "response":
                        if (responseText != null) {
                            throw duplicate(name, index);
                        }
                        responseBase64 = hasTrueBase64Attribute(reader, name, index);
                        responseText = readText(reader, maxBase64Characters(MAX_RESPONSE_BYTES));
                        break;
                    default:
                        skipSimpleElement(reader);
                }
            } else if (event == XMLStreamConstants.END_ELEMENT && "item".equals(reader.getLocalName())) {
                break;
            } else if (event == XMLStreamConstants.CHARACTERS && !reader.isWhiteSpace()) {
                throw new ImportException("Unexpected text in item " + index);
            }
        }

        if (host == null || portText == null || protocol == null || requestText == null) {
            throw new ImportException("Item " + index + " is missing host, port, protocol, or request");
        }
        if (!requestBase64) {
            throw new ImportException("Item " + index + " request must declare base64=\"true\"");
        }
        if (responseText != null && !responseBase64) {
            throw new ImportException("Item " + index + " response must declare base64=\"true\"");
        }

        String normalizedHost = validateHost(host.trim(), index);
        int port = parsePort(portText.trim(), index);
        boolean secure = parseProtocol(protocol.trim(), index);
        byte[] request = decode(requestText, MAX_REQUEST_BYTES, "request", index);
        byte[] response = responseText == null ? null
                : decode(responseText, MAX_RESPONSE_BYTES, "response", index);
        if (request.length == 0) {
            throw new ImportException("Item " + index + " has an empty request");
        }
        if (responseText != null && response.length == 0) {
            throw new ImportException("Item " + index + " has an empty response");
        }
        return new BurpItem(normalizedHost, port, secure, request, response);
    }

    private static String readText(XMLStreamReader reader, int maximum)
            throws XMLStreamException, ImportException {
        StringBuilder value = new StringBuilder(Math.min(maximum, 8192));
        while (reader.hasNext()) {
            int event = reader.next();
            rejectDangerousEvent(reader, event);
            if (event == XMLStreamConstants.START_ELEMENT) {
                throw new ImportException("Nested XML elements are not accepted");
            }
            if (event == XMLStreamConstants.END_ELEMENT) {
                return value.toString();
            }
            if (event == XMLStreamConstants.CHARACTERS || event == XMLStreamConstants.CDATA
                    || event == XMLStreamConstants.SPACE) {
                if ((long) value.length() + reader.getTextLength() > maximum) {
                    throw new ImportException("XML field exceeds its size limit");
                }
                value.append(reader.getTextCharacters(), reader.getTextStart(), reader.getTextLength());
            }
        }
        throw new ImportException("Unexpected end of XML field");
    }

    private static void skipSimpleElement(XMLStreamReader reader)
            throws XMLStreamException, ImportException {
        int characters = 0;
        while (reader.hasNext()) {
            int event = reader.next();
            rejectDangerousEvent(reader, event);
            if (event == XMLStreamConstants.START_ELEMENT) {
                throw new ImportException("Nested XML elements are not accepted");
            }
            if (event == XMLStreamConstants.END_ELEMENT) {
                return;
            }
            if (event == XMLStreamConstants.CHARACTERS || event == XMLStreamConstants.CDATA) {
                characters += reader.getTextLength();
                if (characters > MAX_SMALL_FIELD_CHARS) {
                    throw new ImportException("Metadata field exceeds its size limit");
                }
            }
        }
        throw new ImportException("Unexpected end of XML metadata field");
    }

    private static boolean hasTrueBase64Attribute(XMLStreamReader reader, String field, int index)
            throws ImportException {
        String found = null;
        for (int i = 0; i < reader.getAttributeCount(); i++) {
            if (reader.getAttributeNamespace(i) != null
                    && !reader.getAttributeNamespace(i).isEmpty()) {
                throw new ImportException("Namespaced attributes are not accepted in item " + index);
            }
            if ("base64".equals(reader.getAttributeLocalName(i))) {
                if (found != null) {
                    throw new ImportException("Duplicate base64 attribute on " + field + " in item " + index);
                }
                found = reader.getAttributeValue(i);
            }
        }
        return "true".equals(found);
    }

    private static byte[] decode(String text, int maximum, String field, int index)
            throws ImportException {
        StringBuilder compact = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                continue;
            }
            compact.append(ch);
        }
        if (compact.length() > maxBase64Characters(maximum)) {
            throw new ImportException("Item " + index + " " + field + " exceeds its size limit");
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(compact.toString());
            if (decoded.length > maximum) {
                throw new ImportException("Item " + index + " " + field + " exceeds its size limit");
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            throw new ImportException("Item " + index + " contains invalid Base64 in " + field, e);
        }
    }

    private static int maxBase64Characters(int bytes) {
        return 4 * ((bytes + 2) / 3) + 16_384;
    }

    private static String validateHost(String host, int index) throws ImportException {
        if (host.isEmpty() || host.length() > 255) {
            throw new ImportException("Item " + index + " has an invalid host length");
        }
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        for (int i = 0; i < host.length(); i++) {
            char ch = host.charAt(i);
            if (Character.isISOControl(ch) || Character.isWhitespace(ch)
                    || ch == '/' || ch == '\\' || ch == '?' || ch == '#' || ch == '@') {
                throw new ImportException("Item " + index + " contains an invalid host");
            }
        }
        if (host.indexOf(':') >= 0) {
            if (!host.matches("[0-9A-Fa-f:.]+") || host.chars().filter(ch -> ch == ':').count() < 2) {
                throw new ImportException("Item " + index + " contains an invalid IPv6 host");
            }
            return host;
        }
        try {
            String ascii = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            if (ascii.length() > 253 || ascii.startsWith(".") || ascii.endsWith(".")
                    || ascii.contains("..")) {
                throw new IllegalArgumentException("invalid DNS name");
            }
            for (String label : ascii.split("\\.")) {
                if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
                    throw new IllegalArgumentException("invalid DNS label");
                }
            }
            return ascii;
        } catch (IllegalArgumentException e) {
            throw new ImportException("Item " + index + " contains an invalid host", e);
        }
    }

    private static int parsePort(String value, int index) throws ImportException {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65535) {
                throw new NumberFormatException("out of range");
            }
            return port;
        } catch (NumberFormatException e) {
            throw new ImportException("Item " + index + " has an invalid port", e);
        }
    }

    private static boolean parseProtocol(String value, int index) throws ImportException {
        if ("https".equals(value)) {
            return true;
        }
        if ("http".equals(value)) {
            return false;
        }
        throw new ImportException("Item " + index + " protocol must be http or https");
    }

    private static void rejectNamespace(XMLStreamReader reader) throws ImportException {
        String namespace = reader.getNamespaceURI();
        if (namespace != null && !namespace.isEmpty()) {
            throw new ImportException("XML namespaces are not accepted");
        }
    }

    private static void rejectDangerousEvent(XMLStreamReader reader, int event)
            throws ImportException {
        if (event == XMLStreamConstants.ENTITY_REFERENCE) {
            throw new ImportException("XML entity references are forbidden");
        }
        if (event == XMLStreamConstants.DTD) {
            String declaration = reader.getText();
            if (declaration == null || declaration.length() > MAX_DTD_CHARS) {
                throw new ImportException("XML DTD exceeds the allowed size");
            }
            String normalized = declaration.toUpperCase(Locale.ROOT).replaceAll("\\s+", " ");
            if (normalized.contains("<!ENTITY") || normalized.contains(" SYSTEM ")
                    || normalized.contains(" PUBLIC ")) {
                throw new ImportException("XML entities and external DTDs are forbidden");
            }
        }
    }

    private static String unique(String previous, String value, String field, int index)
            throws ImportException {
        if (previous != null) {
            throw duplicate(field, index);
        }
        return value;
    }

    private static ImportException duplicate(String field, int index) {
        return new ImportException("Duplicate <" + field + "> in item " + index);
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }
}
