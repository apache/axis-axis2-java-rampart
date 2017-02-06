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

You can find a complete tutorial on transport level
security here:
http://wso2.org/library/3190