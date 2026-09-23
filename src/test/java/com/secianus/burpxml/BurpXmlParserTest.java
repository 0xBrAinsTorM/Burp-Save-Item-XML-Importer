package com.secianus.burpxml;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

/** Dependency-free parser regression tests, runnable with a plain JDK. */
public final class BurpXmlParserTest {
    private int passed;

    public static void main(String[] args) throws Exception {
        BurpXmlParserTest suite = new BurpXmlParserTest();
        suite.run();
        System.out.println("Parser tests passed: " + suite.passed);
    }

    private void run() throws Exception {
        validSingleItemRoundTripsBytes(); passed++;
        multipleItemsAreParsed(); passed++;
        requestWithoutResponseIsAccepted(); passed++;
        invalidBase64IsRejected(); passed++;
        missingHostIsRejected(); passed++;
        invalidPortIsRejected(); passed++;
        invalidProtocolIsRejected(); passed++;
        duplicateRequiredFieldIsRejected(); passed++;
        nestedElementIsRejected(); passed++;
        burpInternalDtdIsAccepted(); passed++;
        doctypeAndEntityAreRejected(); passed++;
        externalDtdIsRejected(); passed++;
        nonBase64MessageIsRejected(); passed++;
        namespacedElementIsRejected(); passed++;
    }

    private void validSingleItemRoundTripsBytes() throws Exception {
        byte[] request = new byte[] {'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n',
                'H', 'o', 's', 't', ':', ' ', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', '\r', '\n', '\r', '\n', 0};
        byte[] response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".getBytes(StandardCharsets.ISO_8859_1);
        List<BurpItem> items = parse(xml(item("Example.COM", "443", "https", request, response)));
        check(items.size() == 1, "one item expected");
        check(java.util.Arrays.equals(request, items.get(0).request()), "request bytes changed");
        check(java.util.Arrays.equals(response, items.get(0).response()), "response bytes changed");
        check("example.com".equals(items.get(0).host()), "host not normalized");
        check(items.get(0).secure(), "HTTPS not detected");
    }

    private void multipleItemsAreParsed() throws Exception {
        String first = item("one.example", "80", "http", bytes("GET /1 HTTP/1.1\r\n\r\n"), null);
        String second = item("two.example", "443", "https", bytes("GET /2 HTTP/1.1\r\n\r\n"), bytes("HTTP/1.1 204 No Content\r\n\r\n"));
        check(parse(xml(first + second)).size() == 2, "two items expected");
    }

    private void requestWithoutResponseIsAccepted() throws Exception {
        BurpItem item = parse(xml(item("example.com", "80", "http", bytes("GET / HTTP/1.0\r\n\r\n"), null))).get(0);
        check(!item.hasResponse(), "response should be absent");
    }

    private void invalidBase64IsRejected() throws Exception {
        reject(xml("<item><host>x.test</host><port>80</port><protocol>http</protocol>"
                + "<request base64=\"true\">%%%INVALID%%%</request></item>"), "invalid Base64");
    }

    private void missingHostIsRejected() throws Exception {
        reject(xml("<item><port>80</port><protocol>http</protocol><request base64=\"true\">R0VUIC8=</request></item>"), "missing");
    }

    private void invalidPortIsRejected() throws Exception {
        reject(xml(item("example.com", "70000", "http", bytes("GET /"), null)), "invalid port");
    }

    private void invalidProtocolIsRejected() throws Exception {
        reject(xml(item("example.com", "80", "ftp", bytes("GET /"), null)), "protocol");
    }

    private void duplicateRequiredFieldIsRejected() throws Exception {
        reject(xml("<item><host>a.test</host><host>b.test</host><port>80</port><protocol>http</protocol>"
                + "<request base64=\"true\">R0VUIC8=</request></item>"), "Duplicate");
    }

    private void nestedElementIsRejected() throws Exception {
        reject(xml("<item><host><x>example.com</x></host><port>80</port><protocol>http</protocol>"
                + "<request base64=\"true\">R0VUIC8=</request></item>"), "Nested");
    }

    private void doctypeAndEntityAreRejected() throws Exception {
        String malicious = "<?xml version=\"1.0\"?><!DOCTYPE items [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                + "<items><item><host>&xxe;</host><port>80</port><protocol>http</protocol>"
                + "<request base64=\"true\">R0VUIC8=</request></item></items>";
        reject(malicious, "DTD");
    }

    private void burpInternalDtdIsAccepted() throws Exception {
        String burpDtd = "<?xml version=\"1.0\"?><!DOCTYPE items ["
                + "<!ELEMENT items (item*)><!ATTLIST items burpVersion CDATA \"\">"
                + "<!ELEMENT item (host,port,protocol,request,response?)>"
                + "<!ELEMENT host (#PCDATA)><!ELEMENT port (#PCDATA)>"
                + "<!ELEMENT protocol (#PCDATA)><!ELEMENT request (#PCDATA)>"
                + "<!ATTLIST request base64 (true|false) \"false\">"
                + "<!ELEMENT response (#PCDATA)><!ATTLIST response base64 (true|false) \"false\">]>"
                + "<items burpVersion=\"2026.7\">"
                + item("example.com", "443", "https", bytes("GET / HTTP/1.1\r\n\r\n"),
                bytes("HTTP/1.1 200 OK\r\n\r\n")) + "</items>";
        check(parse(burpDtd).size() == 1, "Burp internal DTD should be accepted");
    }

    private void externalDtdIsRejected() throws Exception {
        reject("<?xml version=\"1.0\"?><!DOCTYPE items SYSTEM \"https://attacker.invalid/items.dtd\">"
                + "<items></items>", "external DTD");
    }

    private void nonBase64MessageIsRejected() throws Exception {
        reject(xml("<item><host>x.test</host><port>80</port><protocol>http</protocol>"
                + "<request>GET /</request></item>"), "base64");
    }

    private void namespacedElementIsRejected() throws Exception {
        reject("<items xmlns=\"urn:not-burp\"><item/></items>", "namespace");
    }

    private static List<BurpItem> parse(String document) throws Exception {
        Path temporaryDirectory = Path.of("build", "test-temp");
        Files.createDirectories(temporaryDirectory);
        Path file = Files.createTempFile(temporaryDirectory, "burp-xml-test-", ".xml");
        try {
            Files.writeString(file, document, StandardCharsets.UTF_8);
            return new BurpXmlParser().parse(file);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static void reject(String document, String expected) throws Exception {
        try {
            parse(document);
            throw new AssertionError("Expected rejection containing: " + expected);
        } catch (ImportException e) {
            check(e.getMessage().toLowerCase().contains(expected.toLowerCase()),
                    "unexpected rejection: " + e.getMessage());
        }
    }

    private static String xml(String items) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><items burpVersion=\"2026.7\">" + items + "</items>";
    }

    private static String item(String host, String port, String protocol, byte[] request, byte[] response) {
        return "<item><time>Wed Sep 23 09:04:48 UTC 2026</time><host>" + host + "</host><port>" + port
                + "</port><protocol>" + protocol + "</protocol><request base64=\"true\">"
                + Base64.getEncoder().encodeToString(request) + "</request>"
                + (response == null ? "" : "<response base64=\"true\">"
                + Base64.getEncoder().encodeToString(response) + "</response>") + "</item>";
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

}
