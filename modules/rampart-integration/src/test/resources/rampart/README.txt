# Please read the file below first as anything in those tests were re-used when possible:
# modules/rampart-tests/test-resources/keys/README.txt
# These were the commands used to generate all the files in the dir: 
# modules/rampart-integration/src/test/resources/rampart
openssl genrsa -out modules/rampart-integration/src/test/resources/rampart/ip.key 2048
openssl req -new -subj '/O=apache.org/OU=eng (NOT FOR PRODUCTION)/CN=ip' -x509 -key modules/rampart-integration/src/test/resources/rampart/ip.key -days 10000 -out modules/rampart-integration/src/test/resources/rampart/ip.crt
openssl pkcs12 -inkey modules/rampart-integration/src/test/resources/rampart/ip.key -in modules/rampart-integration/src/test/resources/rampart/ip.crt -export -out modules/rampart-integration/src/test/resources/rampart/ip.pfx
/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool -importkeystore -srckeystore modules/rampart-integration/src/test/resources/rampart/ip.pfx -destkeystore modules/rampart-integration/src/test/resources/rampart/sts2024.pkcs12 -srcalias 1 -destalias ip -deststoretype pkcs12 -destkeypass password
/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool -importkeystore -srckeystore modules/rampart-tests/test-resources/keys/alice.pfx -destkeystore modules/rampart-integration/src/test/resources/rampart/sts2024.pkcs12 -srcalias 1 -destalias alice -deststoretype pkcs12 -destkeypass password
/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool -importkeystore -srckeystore modules/rampart-tests/test-resources/keys/bob.pfx -destkeystore modules/rampart-integration/src/test/resources/rampart/sts2024.pkcs12 -srcalias 1 -destalias bob -deststoretype pkcs12 -destkeypass password
/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool -import -keystore modules/rampart-integration/src/test/resources/rampart/sts2024.pkcs12 -trustcacerts -alias ca -file modules/rampart-tests/test-resources/keys/ca.crt
