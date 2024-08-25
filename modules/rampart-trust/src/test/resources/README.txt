# Please read the files below first as anything in those tests were re-used when possible:
# modules/rampart-tests/test-resources/keys/README.txt
# modules/rampart-integration/src/test/resources/rampart/README.txt
# These were the commands used to generate all the files in the dir: 
# modules/rampart-trust/src/test/resources
openssl genrsa -out modules/rampart-trust/src/test/resources/apache.key 2048
openssl req -new -subj '/O=apache.org/OU=eng (NOT FOR PRODUCTION)/CN=Apache Org' -x509 -key modules/rampart-trust/src/test/resources/apache.key -days 10000 -out modules/rampart-trust/src/test/resources/apache.crt
openssl pkcs12 -inkey modules/rampart-trust/src/test/resources/apache.key -in modules/rampart-trust/src/test/resources/apache.crt -export -out modules/rampart-trust/src/test/resources/apache.pfx
/usr/lib/jvm/java-17-openjdk-amd64/bin/keytool -importkeystore -srckeystore modules/rampart-trust/src/test/resources/apache.pfx -destkeystore modules/rampart-trust/src/test/resources/apache.pkcs12 -srcalias 1 -destalias apache -deststoretype pkcs12 -destkeypass password
