UsernameToken Authentication

The policy uses a TransportBinding and requires a SignedSupportingToken which 
is a UsernameToken and the inclusion of a TimeStamp. 

Note that Rampart enforces the use of HTTPS transport and that 
{http://ws.apache.org/rampart/policy}RampartConfig assertion provides
additional information required to secure the message.

The policy included in the services.xml file has the following comment :
<!--<sp:HttpsToken RequireClientCertificate="false"/> -->

If you uncomment this and deploy the service you will see the following error message :
org.apache.axis2.AxisFault: Expected transport is "https" but incoming transport found : "http"

For more information on transport level security with Apache Rampart,
please refer to:
- Apache Rampart Quick Start Guide: ../../../src/site/xdoc/quick-start.xml
- Apache Rampart Configuration Guide: ../../../src/site/xdoc/rampartconfig-guide.xml

The original WSO2 tutorial (http://wso2.org/library/3190) is no longer available at that URL.
For current WSO2 documentation that may contain similar content, check:
- WSO2 Documentation: https://wso2.com/documentation/
- WSO2 Technical Docs: https://docs.wso2.com/
- WSO2 GitHub: https://github.com/wso2