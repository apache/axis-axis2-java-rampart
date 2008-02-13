======================================================
Apache Rampart-1.2 build  (May 29, 2007)

http://ws.apache.org/axis2/modules/rampart/
------------------------------------------------------

___________________
Contents
===================

lib      - This directory contains all the libraries required by rampart
           in addition to the libraries available in the axis2 standard binary 
           release.
	   

rampart-1.2.mar   - WS-Security and WS-SecureConversation support for Axis2
rahas-1.2.mar     - STS module - to be used to add STS operations to a service

samples  - This contains samples on using Apache Rampart and configuring
           different components to carryout different WS-Sec* operations.

README.txt - This file

build.xml - Setup file to copy all jars to required places

IMPORTANT: 
Before you build rampart from source distribution, you need provision for 
unlimited security jurisdiction as some of the test cases use key size of
256. So you need to download jce_policy-x_y_z.zip (relevant to your JDK version)
and extract the jar files local_policy.jar and US_export_policy.jar to 
$JAVA_HOME/jre/lib/security. These files are listed in sun download site,
under the your JDK version as Java(TM) Cryptography Extension (JCE) Unlimited 
Strength Jurisdiction Policy Files.     

Before you engage Rampart 
You have to make a small change to the default axis2.xml by adding the security 
phase to OutFaultFlow. Security phase should be added just after the MessageOut 
phase.

eg.
<phaseOrder type="OutFaultFlow">
    <!--      user can add his own phases to this area  -->
    <phase name="OperationOutFaultPhase"/>
    <phase name="RMPhase"/>
    <phase name="PolicyDetermination"/>
    <phase name="MessageOut"/>
    *<phase name="Security"/>* 
</phaseOrder>
 

Before you try any of the samples makesure you

1.) Have the Axis2 standard binary distribution downloaded and extracted.
2.) Set the AXIS2_HOME environment variable
3.) Run ant from the "samples" directory to copy the required libraries and
    modules to relevant directories in AXIS2_HOME.
4.) Download xalan-2.7.0.jar from here[1] and put under AXIS2_HOME\lib folder,
    if you use JDK 1.5.


___________________
Crypto Notice
===================

   This distribution includes cryptographic software.  The country in 
   which you currently reside may have restrictions on the import, 
   possession, use, and/or re-export to another country, of 
   encryption software.  BEFORE using any encryption software, please 
   check your country's laws, regulations and policies concerning the
   import, possession, or use, and re-export of encryption software, to 
   see if this is permitted.  See <http://www.wassenaar.org/> for more
   information.

   The U.S. Government Department of Commerce, Bureau of Industry and
   Security (BIS), has classified this software as Export Commodity 
   Control Number (ECCN) 5D002.C.1, which includes information security
   software using or performing cryptographic functions with asymmetric
   algorithms.  The form and manner of this Apache Software Foundation
   distribution makes it eligible for export under the License Exception
   ENC Technology Software Unrestricted (TSU) exception (see the BIS 
   Export Administration Regulations, Section 740.13) for both object 
   code and source code.

   The following provides more details on the included cryptographic
   software:

   Apache Santuario : http://santuario.apache.org/
   Apache WSS4J     : http://ws.apache.org/wss4j/
   Bouncycastle     : http://www.bouncycastle.org/

___________________
Support
===================
 
Any problem with this release can be reported to Axis mailing list
or in the JIRA issue tracker. If you are sending an email to the mailing
list make sure to add the [Rampart] prefix to the subject.

Mailing list subscription:
    axis-dev-subscribe@ws.apache.org

Jira:
    http://issues.apache.org/jira/browse/AXIS2
    (Component - modules)


Thank you for using Apache Rampart!

The Apache Rampart team. 

[1] http://www.apache.org/dist/java-repository/xalan/jars/
