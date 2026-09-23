# Burp-Save-Item-XML-Importer
Burp Suite extension for importing saved Request/Response XML items back into the Site Map.
# Burp Save Item XML Importer

A small Burp Suite extension that imports XML files created through **Save item(s)** back into **Target → Site map**, including the original request and response.

The extension never sends imported requests automatically.

## Features

* Imports single or multiple Burp XML items
* Restores requests and stored responses
* Supports Burp’s internal XML DTD
* Rejects external DTDs and XML entities
* Validates Base64 data, hosts, ports, and protocols
* Uses the modern Montoya API
* Performs no network communication

## Installation

1. Download the latest JAR from [Releases](../../releases).
2. Open **Extensions → Installed** in Burp Suite.
3. Click **Add** and select **Java** as the extension type.
4. Select the downloaded JAR.
5. Open the **Save Item XML Importer** tab.

## Usage

1. In Burp, save one or more HTTP history items using **Save item(s)**.
2. Open the importer tab.
3. Click **Import Burp XML** and select the exported XML file.
4. Find the imported entries under **Target → Site map**.
5. Send a request to Repeater if required.

Imported requests are not replayed automatically.

## Build

The project requires Java 17 or newer.

```bash
gradle clean check jar
```

The resulting JAR is created under:

```text
build/libs/
```

## License

MIT
