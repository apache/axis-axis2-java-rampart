# These were the commands used to generate all the files in the dir: 
# modules/rampart-tests/test-resources/keys
# The unit tests written circa 2005 for the certs that expired many years later
# in the now deleted interop2.jks, can be roughly summarized as using a Bob identity for 
# the service and an Alice identity for the client.
# Passwords for every private key is 'password' (no quotes). 
# The file interop2024.pkcs12 is the replacement for interop2.jks; the rest of the files are left
# to show how interop2024.pkcs12 was created.
# To summarize, interop2024.pkcs12 has private keys for Alice and Bob as a keystore while the ca.crt file is
# added as a trust store.
# Everything shown is for a self-signed CA without an intermediary CA, which the original
# interop2.jks file had. See the link below for the obsolete and expired origins of interop2.jks.
# https://svn-master.apache.org/repos/asf/webservices/wss4j/branches/WSS4J_1_0_0_FINAL/interop/keys/README.txt
openssl genrsa -out modules/rampart-tests/test-resources/keys/ca.key 2048
openssl genrsa -out modules/rampart-tests/test-resources/keys/alice.key 2048
openssl genrsa -out modules/rampart-tests/test-resources/keys/bob.key 2048
openssl req -x509 -new -subj '/O=apache.org/OU=eng (NOT FOR PRODUCTION)/CN=ca' -key modules/rampart-tests/test-resources/keys/ca.key -nodes -out modules/rampart-tests/test-resources/keys/ca.pem -days 10000 -extensions v3_req
openssl req -new -subj '/O=apache.org/OU=eng (NOT FOR PRODUCTION)/CN=ca' -x509 -key modules/rampart-tests/test-resources/keys/ca.key -days 10000 -out modules/rampart-tests/test-resources/keys/ca.crt
openssl req -new -subj '/O=apache.org/OU=eng (NOT FOR PRODUCTION)/CN=alice' -x509 -key modules/rampart-tests/test-resources/keys/alice.key -days 10000 -out modules/rampart-tests/test-resources/keys/alice.crt
openssl req -new -subj '/O=apache.org/OU=eng (NOT FOR PRODUCTION)/CN=bob' -x509 -key modules/rampart-tests/test-resources/keys/bob.key -days 10000 -out modules/rampart-tests/test-resources/keys/bob.crt
openssl pkcs12 -inkey modules/rampart-tests/test-resources/keys/ca.key -in modules/rampart-tests/test-resources/keys/ca.crt -export -out modules/rampart-tests/test-resources/keys/ca.pfx
openssl pkcs12 -inkey modules/rampart-tests/test-resources/keys/alice.key -in modules/rampart-tests/test-resources/keys/alice.crt -export -out modules/rampart-tests/test-resources/keys/alice.pfx
openssl pkcs12 -inkey modules/rampart-tests/test-resources/keys/bob.key -in modules/rampart-tests/test-resources/keys/bob.crt -export -out modules/rampart-tests/test-resources/keys/bob.pfx
/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool -importkeystore -srckeystore modules/rampart-tests/test-resources/keys/alice.pfx -destkeystore modules/rampart-tests/test-resources/keys/interop2024.pkcs12 -srcalias 1 -destalias alice -deststoretype pkcs12 -destkeypass password
/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool -importkeystore -srckeystore modules/rampart-tests/test-resources/keys/bob.pfx -destkeystore modules/rampart-tests/test-resources/keys/interop2024.pkcs12 -srcalias 1 -destalias bob -deststoretype pkcs12 -destkeypass password
/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool -import -keystore modules/rampart-tests/test-resources/keys/interop2024.pkcs12 -trustcacerts -alias ca -file modules/rampart-tests/test-resources/keys/ca.crt
