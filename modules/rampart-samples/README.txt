********************************************************************************
**************************** Apache Rampart Samples ****************************
********************************************************************************

This directory contains three sub directories:

    - basic - A set of samples that uses basic rampart configuration using 
    	          parameters

    - policy - A set of samples that uses rampart with WS-SecurityPolicy
    
    - keys   - The keystore files that contains the keys used by the samples

Please use Apache Ant with the build.xml file available in the top level directory
to copy all jars and mars to required places. Simply execute the ant command with 
no arguments.

AXIS2_HOME must be set as an environment variable for the ant command to copy the 
Rampart jars to AXIS2_HOME/lib. 

The policy samples each have an Ant target for both the client and server 
(SimpleHTTPServer from the Axis2 test suite) i.e. they need to run in separate shells from the samples dir. 

For example, in one shell (repeat for samples 1-9): 

ant -buildfile policy/build.xml service.01

Then in another shell:

ant -buildfile policy/build.xml client.01
