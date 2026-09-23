#!/usr/bin/env sh
set -eu

mkdir -p build/stubs build/classes build/testclasses build/libs

find compile-stubs -name '*.java' -print | sort > build/stub-sources.txt
find src/main/java -name '*.java' -print | sort > build/main-sources.txt
find src/test/java -name '*.java' -print | sort > build/test-sources.txt

javac --release 17 -d build/stubs @build/stub-sources.txt
javac --release 17 -cp build/stubs -d build/classes @build/main-sources.txt
javac --release 17 -cp build/classes -d build/testclasses @build/test-sources.txt
java -cp build/classes:build/testclasses com.secianus.burpxml.BurpXmlParserTest

cp -R src/main/resources/. build/classes/
jar --create --file build/libs/burp-save-item-importer-1.0.1.jar -C build/classes .

echo "Created build/libs/burp-save-item-importer-1.0.1.jar"
