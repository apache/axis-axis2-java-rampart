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

Before you try any of the samples makesure you

1.) Have the Axis2 standard binary distribution downloaded and extracted.
2.) Set the AXIS2_HOME environment variable
3.) Run ant from the "samples" directory to copy the required libraries and
    modules to relevant directories in AXIS2_HOME.
4.) Download xalan-2.7.0.jar from here[1] and put under AXIS2_HOME\lib folder,
    if you use JDK 1.5.

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
