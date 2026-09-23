# Burp Save Item XML Importer

A small Burp Suite extension that imports Burp's own **Save item(s)** XML files
into **Target > Site map**. Imported requests and stored responses remain local;
the extension never sends an HTTP request.

## Install

1. Open **Extensions > Installed** in Burp Suite.
2. Select **Add**, choose extension type **Java**, and select
   `burp-save-item-importer-1.0.1.jar`.
3. Open the new **Save Item XML Importer** suite tab.
4. Select **Import Burp XML**, choose a trusted XML export, and review the
   import result.
5. Find the imported item under **Target > Site map**. You can send its request
   to Repeater from there.

Use a current Burp Suite release. The extension targets Montoya API 2026.7 and
Java 17 bytecode.

## Security properties

- Burp's internal schema DTD is accepted but never processed. Entity
  declarations, external DTDs, and entity references are rejected.
- XML is parsed as a stream with explicit file, item, field, request, and
  response limits.
- `request` and `response` must use `base64="true"`; Base64 is validated
  strictly after removing ASCII whitespace.
- Only `http` and `https`, ports 1-65535, and non-control host values are
  accepted.
- Duplicate required fields are rejected.
- The importer performs no network access and never replays a request.

Current limits: 50 MiB XML file, 10,000 items, 10 MiB per request, 30 MiB per
response. Burp's Site Map may replace an existing matching entry.

## Rebuild

With JDK 17+ and Gradle installed:

```sh
gradle clean check jar
```

The Montoya API is a compile-only dependency and is not bundled in the JAR.
