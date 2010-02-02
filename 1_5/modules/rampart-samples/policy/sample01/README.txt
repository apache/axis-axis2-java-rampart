UsernameToken Authentication

The policy uses a TransportBinding and requires a SignedSupportingToken which 
is a UsernameToken and the inclusion of a TimeStamp. 

Note that Rampart enforces the use of HTTPS transport and that 
{http://ws.apache.org/rampart/policy}RampartConfig assertion provides
additional information required to secure the message.

Expected result :
org.apache.axis2.AxisFault: Expected transport is "https" but incoming transport found : "http"

This sample uses http transport while the policy enforces https transport. Thus you
get a error message as mentioned above. You can find a complete tutorial on transport level
security here.
http://wso2.org/library/3190

