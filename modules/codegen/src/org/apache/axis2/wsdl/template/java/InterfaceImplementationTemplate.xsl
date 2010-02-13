<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="text"/>

    <!-- import the databinding template-->
    <xsl:include href="databindsupporter"/>
    <!-- import the other templates for databinding
         Note  -  these names would be handled by a special
         URI resolver during the xslt transformations
     -->
    <xsl:include href="externalTemplate"/>
    
    
    <xsl:include href="policyExtensionTemplate"/>

    <xsl:template match="/class">
        <xsl:variable name="interfaceName"><xsl:value-of select="@interfaceName"/></xsl:variable>
        <xsl:variable name="package"><xsl:value-of select="@package"/></xsl:variable>
        <xsl:variable name="callbackname"><xsl:value-of select="@callbackname"/></xsl:variable>
        <xsl:variable name="isSync"><xsl:value-of select="@isSync"/></xsl:variable>
        <xsl:variable name="isAsync"><xsl:value-of select="@isAsync"/></xsl:variable>
        <xsl:variable name="soapVersion"><xsl:value-of select="@soap-version"/></xsl:variable>
        /**
        * <xsl:value-of select="@name"/>.java
        *
        * This file was auto-generated from WSDL
        * by the Apache Axis2 version: #axisVersion# #today#
        */
        package <xsl:value-of select="$package"/>;

        <!-- Put the MTOM enable flag -->

        /*
        *  <xsl:value-of select="@name"/> java implementation
        */

        <xsl:variable name="fullyQualifiedClassName"><xsl:value-of select="$package"/>.<xsl:value-of select="@name"/></xsl:variable>
        public class <xsl:value-of select="@name"/> extends org.apache.axis2.client.Stub
        <xsl:if test="not(@wrapped)">implements <xsl:value-of select="$interfaceName"/></xsl:if>{
        protected org.apache.axis2.description.AxisOperation[] _operations;

        //hashmaps to keep the fault mapping
        private java.util.HashMap faultExeptionNameMap = new java.util.HashMap();
        private java.util.HashMap faultExeptionClassNameMap = new java.util.HashMap();
        private java.util.HashMap faultMessageMap = new java.util.HashMap();

    
    private void populateAxisService() throws org.apache.axis2.AxisFault {

     //creating the Service with a unique name
     _service = new org.apache.axis2.description.AxisService("<xsl:value-of select="@servicename"/>" + this.hashCode());
     
    <xsl:if test="@policy">     
     java.lang.String _endpoint_policy_string = "<xsl:value-of select="@policy"/>";
     org.apache.neethi.Policy _endpoint_policy = getPolicy(_endpoint_policy_string);
     ((org.apache.axis2.description.PolicyInclude) _service.getPolicyInclude()).setPolicy(_endpoint_policy);
    </xsl:if>

        //creating the operations
        org.apache.axis2.description.AxisOperation __operation;
    <xsl:if test="//method[@policy]">
    java.lang.String __operation_policy_string;
    </xsl:if>


        _operations = new org.apache.axis2.description.AxisOperation[<xsl:value-of select="count(method)"/>];
        <xsl:for-each select="method">
            <xsl:choose>
                <xsl:when test="@mep='10'">
                    __operation = new org.apache.axis2.description.OutOnlyAxisOperation();
                </xsl:when>
                <xsl:when test="@mep='11'">
                    __operation = new org.apache.axis2.description.RobustOutOnlyAxisOperation();
                </xsl:when>
                <xsl:otherwise>
                   __operation = new org.apache.axis2.description.OutInAxisOperation();
                </xsl:otherwise>
            </xsl:choose>

            __operation.setName(new javax.xml.namespace.QName("<xsl:value-of select="@namespace"/>", "<xsl:value-of select="@name"/>"));
	    _service.addOperation(__operation);
	    
	    <xsl:if test="input/@policy">
	    (__operation).getMessage(org.apache.axis2.wsdl.WSDLConstants.MESSAGE_LABEL_OUT_VALUE).getPolicyInclude().setPolicy(getPolicy("<xsl:value-of select="input/@policy"/>"));
	    </xsl:if>
	    
	    <xsl:if test="output/@policy">
	    (__operation).getMessage(org.apache.axis2.wsdl.WSDLConstants.MESSAGE_LABEL_IN_VALUE).getPolicyInclude().setPolicy(getPolicy("<xsl:value-of select="output/@policy"/>"));
	    </xsl:if>
	    
            _operations[<xsl:value-of select="position()-1"/>]=__operation;
            
        </xsl:for-each>
        }

    //populates the faults
    private void populateFaults(){
         <xsl:for-each select="method">
           <xsl:for-each select="fault/param">
              faultExeptionNameMap.put( new javax.xml.namespace.QName(
                 "<xsl:value-of select="@namespace"/>",
                 "<xsl:value-of select="@localname"/>"),
                 "<xsl:value-of select="@name"/>"
               );
              faultExeptionClassNameMap.put(new javax.xml.namespace.QName(
                "<xsl:value-of select="@namespace"/>",
                "<xsl:value-of select="@localname"/>"),
                "<xsl:value-of select="@name"/>");
               faultMessageMap.put( new javax.xml.namespace.QName(
                 "<xsl:value-of select="@namespace"/>",
                 "<xsl:value-of select="@localname"/>"),
                 "<xsl:value-of select="@instantiatableType"/>"
               );
           </xsl:for-each>
        </xsl:for-each>


    }

   /**
    Constructor that takes in a configContext
    */
   public <xsl:value-of select="@name"/>(org.apache.axis2.context.ConfigurationContext configurationContext,
        java.lang.String targetEndpoint)
        throws org.apache.axis2.AxisFault {
         //To populate AxisService
         populateAxisService();
         populateFaults();

        _serviceClient = new org.apache.axis2.client.ServiceClient(configurationContext,_service);
        <xsl:if test="@policy">
        _service.applyPolicy();
        </xsl:if>
	
        configurationContext = _serviceClient.getServiceContext().getConfigurationContext();

        _serviceClient.getOptions().setTo(new org.apache.axis2.addressing.EndpointReference(
                targetEndpoint));
        <xsl:if test="$soapVersion='1.2'">
            //Set the soap version
            _serviceClient.getOptions().setSoapVersionURI(org.apache.axiom.soap.SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI);
        </xsl:if>
    
    }

    /**
     * Default Constructor
     */
    public <xsl:value-of select="@name"/>() throws org.apache.axis2.AxisFault {
        <xsl:for-each select="endpoint">
            <xsl:choose>
                <xsl:when test="position()=1">
                    this("<xsl:value-of select="."/>" );
                </xsl:when>
                <xsl:otherwise>
                    //this("<xsl:value-of select="."/>" );
                </xsl:otherwise>
            </xsl:choose>
        </xsl:for-each>
    }

    /**
     * Constructor taking the target endpoint
     */
    public <xsl:value-of select="@name"/>(java.lang.String targetEndpoint) throws org.apache.axis2.AxisFault {
        this(null,targetEndpoint);
    }



        <xsl:for-each select="method">
                        
          <!-- If usedbmethod attribute present, gives name of method to call for implementation -->
          <xsl:variable name="usedbimpl"><xsl:value-of select="@usdbimpl"/></xsl:variable>
          <xsl:if test="$usedbimpl!='true'">
          
            <xsl:variable name="outputtype"><xsl:value-of select="output/param/@type"></xsl:value-of></xsl:variable>
            <xsl:variable name="style"><xsl:value-of select="@style"></xsl:value-of></xsl:variable>
            <xsl:variable name="soapAction"><xsl:value-of select="@soapaction"></xsl:value-of></xsl:variable>
            <xsl:variable name="mep"><xsl:value-of select="@mep"/></xsl:variable>
        
        <!-- MTOM -->
        <xsl:variable name="method-name"><xsl:value-of select="@name"/></xsl:variable>
        <xsl:variable name="method-ns"><xsl:value-of select="@namespace"/> </xsl:variable>
        <!-- MTOM -->

            <!-- Code generation for the in-out mep -->
            <xsl:if test="$mep='12'">  <!-- These constants can be found in org.apache.axis2.wsdl.WSDLConstants -->
                <xsl:if test="$isSync='1'">
                    /**
                    * Auto generated method signature
                    * @see <xsl:value-of select="$package"/>.<xsl:value-of select="$interfaceName"/>#<xsl:value-of select="@name"/>
                    <xsl:for-each select="input/param[@type!='']">
                        * @param <xsl:value-of select="@name"></xsl:value-of><xsl:text>
                    </xsl:text></xsl:for-each>
                    */
                    public <xsl:choose><xsl:when test="$outputtype=''">void</xsl:when><xsl:otherwise><xsl:value-of select="$outputtype"/></xsl:otherwise></xsl:choose>
                    <xsl:text> </xsl:text><xsl:value-of select="@name"/>(

                    <xsl:variable name="inputcount" select="count(input/param[@location='body' and @type!=''])"/>
                    <xsl:choose>
                        <xsl:when test="$inputcount=1">
                            <!-- Even when the parameters are 1 we have to see whether we have the
                          wrapped parameters -->
                            <xsl:variable name="inputWrappedCount" select="count(input/param[@location='body' and @type!='']/param)"/>
                            <xsl:choose>
                                <xsl:when test="$inputWrappedCount &gt; 0">
                                   <xsl:for-each select="input/param[@location='body' and @type!='']/param">
                                        <xsl:if test="position()>1">,</xsl:if><xsl:value-of select="@type"/><xsl:text> </xsl:text><xsl:value-of select="@name"/>
                                    </xsl:for-each>
                                </xsl:when>
                                <xsl:otherwise>
                                    <xsl:value-of select="input/param[@location='body' and @type!='']/@type"/><xsl:text> </xsl:text><xsl:value-of select="input/param[@location='body' and @type!='']/@name"/>
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:when>
                        <xsl:otherwise><!-- Just leave it - nothing we can do here --></xsl:otherwise>
                    </xsl:choose>

                    <xsl:if test="$inputcount=1 and input/param[not(@location='body') and @type!='']">,</xsl:if>
                    <xsl:for-each select="input/param[not(@location='body') and @type!='']">
                        <xsl:if test="position()>1">,</xsl:if><xsl:value-of select="@type"/><xsl:text> </xsl:text><xsl:value-of select="@name"/>
                    </xsl:for-each>)
                    throws java.rmi.RemoteException
                    <!--add the faults-->
                    <xsl:for-each select="fault/param[@type!='']">
                        ,<xsl:value-of select="@name"/>
                    </xsl:for-each>{
              try{
               org.apache.axis2.client.OperationClient _operationClient = _serviceClient.createClient(_operations[<xsl:value-of select="position()-1"/>].getName());
              _operationClient.getOptions().setAction("<xsl:value-of select="$soapAction"/>");
              _operationClient.getOptions().setExceptionToBeThrownOnSOAPFault(true);

              <!--todo if the stub was generated with unwrapping, wrap all parameters into a single element-->

              // create SOAP envelope with that payload
              org.apache.axiom.soap.SOAPEnvelope env = null;
                    <xsl:variable name="count" select="count(input/param[@type!=''])"/>
                    <xsl:choose>
                        <!-- test the number of input parameters
                        If the number of parameter is more then just run the normal test-->
                        <xsl:when test="$count &gt; 0">
                            <xsl:choose>
                                <!-- style being doclit or rpc does not matter -->
                                <xsl:when test="$style='rpc' or $style='document'">
                                    //Style is Doc.
                                    <xsl:variable name="inputcount" select="count(input/param[@location='body' and @type!=''])"/>
                                    <xsl:choose>
                                        <xsl:when test="$inputcount=1">
                                            <!-- Even when the parameters are 1 we have to see whether we have the
                                                wrapped parameters -->
                                           <xsl:variable name="inputWrappedCount" select="count(input/param[@location='body' and @type!='']/param)"/>
                                           <xsl:variable name="inputElementType" select="input/param[@location='body' and @type!='']/@type"></xsl:variable>

                                            <xsl:choose>
                                                <xsl:when test="$inputWrappedCount &gt; 0">
                                                    <xsl:value-of select="$inputElementType"/><xsl:text> </xsl:text>dummyWrappedType = null;
                                                    env = toEnvelope(getFactory(_operationClient.getOptions().getSoapVersionURI()),
                                                    <xsl:for-each select="input/param[@location='body' and @type!='']/param">
                                                        <xsl:value-of select="@name"/>,
                                                    </xsl:for-each>dummyWrappedType,
                                                    optimizeContent(new javax.xml.namespace.QName("<xsl:value-of select="$method-ns"/>",
                                                    "<xsl:value-of select="$method-name"/>")));
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    <!-- there are no unwrapped parameters - go ahead and use the normal wrapped codegen-->
                                                    env = toEnvelope(getFactory(_operationClient.getOptions().getSoapVersionURI()),
                                                    <xsl:value-of select="input/param[@location='body' and @type!='']/@name"/>,
                                                    optimizeContent(new javax.xml.namespace.QName("<xsl:value-of select="$method-ns"/>",
                                                    "<xsl:value-of select="$method-name"/>")));
                                                </xsl:otherwise>
                                            </xsl:choose>
                                        </xsl:when>
                                        <xsl:otherwise>
                                              env = toEnvelope(getFactory(_operationClient.getOptions().getSoapVersionURI()));
                                        </xsl:otherwise>
                                    </xsl:choose>

                                   <xsl:if test="count(input/param[@location='header']) &gt; 0">
                                               env.build();
                                    </xsl:if>
                                    <xsl:for-each select="input/param[@location='header']">
                                        // add the children only if the parameter is not null
                                        if (<xsl:value-of select="@name"/>!=null){
                                        env.getHeader().addChild(toOM(<xsl:value-of select="@name"/>, optimizeContent(new javax.xml.namespace.QName("<xsl:value-of select="$method-ns"/>", "<xsl:value-of select="$method-name"/>"))));
                                        }
                                    </xsl:for-each>
                                </xsl:when>
                                <xsl:otherwise>
                                    //Unknown style detected !! No code is generated
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:when>
                        <!-- No input parameters present. So generate assuming no input parameters-->
                        <xsl:otherwise>
                            <xsl:choose>
                                <xsl:when test="$style='rpc' or $style='document'">
                                    //Style is taken to be "document". No input parameters
                                    org.apache.axiom.soap.SOAPFactory factory = getFactory(_operationClient.getOptions().getSoapVersionURI());
                                    env = factory.getDefaultEnvelope();
                                    env.getBody().addChild(factory.createOMElement("<xsl:value-of select="$method-name"/>", "<xsl:value-of select="$method-ns"/>", ""));
                                </xsl:when>
                                <xsl:otherwise>
                                     //Unknown style detected !! No code is generated
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:otherwise>
                    </xsl:choose>
        //adding SOAP headers
         _serviceClient.addHeadersToEnvelope(env);
        // create message context with that soap envelope
        org.apache.axis2.context.MessageContext _messageContext = new org.apache.axis2.context.MessageContext() ;
        _messageContext.setEnvelope(env);

        // add the message contxt to the operation client
        _operationClient.addMessageContext(_messageContext);

        //execute the operation client
        _operationClient.execute(true);

         <xsl:choose>
            <xsl:when test="$outputtype=''">
                return;
            </xsl:when>
            <xsl:otherwise>
               org.apache.axis2.context.MessageContext _returnMessageContext = _operationClient.getMessageContext(
                                           org.apache.axis2.wsdl.WSDLConstants.MESSAGE_LABEL_IN_VALUE);
                org.apache.axiom.soap.SOAPEnvelope _returnEnv = _returnMessageContext.getEnvelope();
                <!-- todo need to change this to cater for unwrapped messages (multiple parts) -->
                <xsl:choose>
                    <xsl:when test="$style='document' or $style='rpc'">
                           java.lang.Object object = fromOM(
                                        _returnEnv.getBody().getFirstElement() ,
                                        <xsl:value-of select="$outputtype"/>.class,
                                         getEnvelopeNamespaces(_returnEnv));
                           _messageContext.getTransportOut().getSender().cleanup(_messageContext);
                           return (<xsl:value-of select="$outputtype"/>)object;
                    </xsl:when>
                    <xsl:otherwise>
                         //Unknown style detected !! No code is generated
                    </xsl:otherwise>
                </xsl:choose>
            </xsl:otherwise>
        </xsl:choose>
         }catch(org.apache.axis2.AxisFault f){
            org.apache.axiom.om.OMElement faultElt = f.getDetail();
            if (faultElt!=null){
                if (faultExeptionNameMap.containsKey(faultElt.getQName())){
                    //make the fault by reflection
                    try{
                        java.lang.String exceptionClassName = (java.lang.String)faultExeptionClassNameMap.get(faultElt.getQName());
                        java.lang.Class exceptionClass = java.lang.Class.forName(exceptionClassName);
                        java.lang.Exception ex=
                                (java.lang.Exception) exceptionClass.newInstance();
                        //message class
                        java.lang.String messageClassName = (java.lang.String)faultMessageMap.get(faultElt.getQName());
                        java.lang.Class messageClass = java.lang.Class.forName(messageClassName);
                        java.lang.Object messageObject = fromOM(faultElt,messageClass,null);
                        java.lang.reflect.Method m = exceptionClass.getMethod("setFaultMessage",
                                   new java.lang.Class[]{messageClass});
                        m.invoke(ex,new java.lang.Object[]{messageObject});
                        <xsl:for-each select="fault/param">
                        if (ex instanceof <xsl:value-of select="@name"/>){
                          throw (<xsl:value-of select="@name"/>)ex;
                        }
                        </xsl:for-each>

                        throw new java.rmi.RemoteException(ex.getMessage(), ex);
                    }catch(java.lang.ClassCastException e){
                       // we cannot intantiate the class - throw the original Axis fault
                        throw f;
                    } catch (java.lang.ClassNotFoundException e) {
                        // we cannot intantiate the class - throw the original Axis fault
                        throw f;
                    }catch (java.lang.NoSuchMethodException e) {
                        // we cannot intantiate the class - throw the original Axis fault
                        throw f;
                    } catch (java.lang.reflect.InvocationTargetException e) {
                        // we cannot intantiate the class - throw the original Axis fault
                        throw f;
                    }  catch (java.lang.IllegalAccessException e) {
                        // we cannot intantiate the class - throw the original Axis fault
                        throw f;
                    }   catch (java.lang.InstantiationException e) {
                        // we cannot intantiate the class - throw the original Axis fault
                        throw f;
                    }
                }else{
                    throw f;
                }
            }else{
                throw f;
            }
        }
        }
            </xsl:if>
            <!-- Async method generation -->
            <xsl:if test="$isAsync='1'">
                /**
                * Auto generated method signature for Asynchronous Invocations
                * @see <xsl:value-of select="$package"/>.<xsl:value-of select="$interfaceName"/>#start<xsl:value-of select="@name"/>
                <xsl:for-each select="input/param[@type!='']">
                    * @param <xsl:value-of select="@name"></xsl:value-of><xsl:text>
                </xsl:text></xsl:for-each>
                */
                public  void start<xsl:value-of select="@name"/>(

                 <xsl:variable name="inputcount" select="count(input/param[@location='body' and @type!=''])"/>
                    <xsl:choose>
                        <xsl:when test="$inputcount=1">
                            <!-- Even when the parameters are 1 we have to see whether we have the
                          wrapped parameters -->
                            <xsl:variable name="inputWrappedCount" select="count(input/param[@location='body' and @type!='']/param)"/>
                            <xsl:choose>
                                <xsl:when test="$inputWrappedCount &gt; 0">
                                   <xsl:for-each select="input/param[@location='body' and @type!='']/param">
                                        <xsl:if test="position()>1">,</xsl:if><xsl:value-of select="@type"/><xsl:text> </xsl:text><xsl:value-of select="@name"/>
                                    </xsl:for-each>
                                </xsl:when>
                                <xsl:otherwise>
                                    <xsl:value-of select="input/param[@location='body' and @type!='']/@type"/><xsl:text> </xsl:text><xsl:value-of select="input/param[@location='body' and @type!='']/@name"/>
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:when>
                        <xsl:otherwise><!-- Just leave it - nothing we can do here --></xsl:otherwise>
                    </xsl:choose>                                                
                    <xsl:if test="$inputcount=1">,</xsl:if>
                    <xsl:for-each select="input/param[not(@location='body') and @type!='']">
                       <xsl:value-of select="@type"/><xsl:text> </xsl:text><xsl:value-of select="@name"/>,
                    </xsl:for-each>

                  final <xsl:value-of select="$package"/>.<xsl:value-of select="$callbackname"/> callback)

                throws java.rmi.RemoteException{

              org.apache.axis2.client.OperationClient _operationClient = _serviceClient.createClient(_operations[<xsl:value-of select="position()-1"/>].getName());
             _operationClient.getOptions().setAction("<xsl:value-of select="$soapAction"/>");
             _operationClient.getOptions().setExceptionToBeThrownOnSOAPFault(true);

          <!--todo if the stub was generated with unwrapping, wrap all parameters into a single element-->

              // create SOAP envelope with that payload
              org.apache.axiom.soap.SOAPEnvelope env=null;
                    <xsl:variable name="count" select="count(input/param[@type!=''])"/>
                    <xsl:choose>
                        <!-- test the number of input parameters
                        If the number of parameter is more then just run the normal test-->
                        <xsl:when test="$count &gt; 0">
                            <xsl:choose>
                                <xsl:when test="$style='document' or $style='rpc'">
                                    //Style is Doc.
                                    <xsl:variable name="inputcount" select="count(input/param[@location='body' and @type!=''])"/>
                                    <xsl:choose>
                                        <xsl:when test="$inputcount=1">
                                            <!-- Even when the parameters are 1 we have to see whether we have the
                                                wrapped parameters -->
                                           <xsl:variable name="inputWrappedCount" select="count(input/param[@location='body' and @type!='']/param)"/>
                                            <xsl:variable name="inputElementType" select="input/param[@location='body' and @type!='']/@type"></xsl:variable>

                                            <xsl:choose>
                                                <xsl:when test="$inputWrappedCount &gt; 0">
                                                    <xsl:value-of select="$inputElementType"/><xsl:text> </xsl:text>dummyWrappedType = null;
                                                    env = toEnvelope(getFactory(_operationClient.getOptions().getSoapVersionURI()),
                                                    <xsl:for-each select="input/param[@location='body' and @type!='']/param">
                                                        <xsl:value-of select="@name"/>,
                                                    </xsl:for-each> dummyWrappedType,
                                                    optimizeContent(new javax.xml.namespace.QName("<xsl:value-of select="$method-ns"/>",
                                                    "<xsl:value-of select="$method-name"/>")));
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    <!-- there are no unwrapped parameters - go ahead and use the normal wrapped codegen-->
                                                    env = toEnvelope(getFactory(_operationClient.getOptions().getSoapVersionURI()),
                                                    <xsl:value-of select="input/param[@location='body' and @type!='']/@name"/>,
                                                    optimizeContent(new javax.xml.namespace.QName("<xsl:value-of select="$method-ns"/>",
                                                    "<xsl:value-of select="$method-name"/>")));
                                                </xsl:otherwise>
                                            </xsl:choose>
                                        </xsl:when>
                                        <xsl:otherwise>
                                              env = toEnvelope(getFactory(_operationClient.getOptions().getSoapVersionURI()));
                                        </xsl:otherwise>
                                    </xsl:choose>

                                    <xsl:for-each select="input/param[@location='header']">
                                         // add the headers only if they are not null
                                        if (<xsl:value-of select="@name"/>!=null){
                                           env.getHeader().addChild(toOM(<xsl:value-of select="@name"/>, optimizeContent(new javax.xml.namespace.QName("<xsl:value-of select="$method-ns"/>", "<xsl:value-of select="$method-name"/>"))));
                                        }
                                    </xsl:for-each>
                                </xsl:when>
                                <xsl:otherwise>
                                    //Unknown style detected !! No code is generated
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:when>
                        <!-- No input parameters present. So generate assuming no input parameters-->
                        <xsl:otherwise>
                            <xsl:choose>
                                <xsl:when test="$style='document' or $style='rpc'">
                                    //Style is Doc. No input parameters
                                    org.apache.axiom.soap.SOAPFactory factory = getFactory(_operationClient.getOptions().getSoapVersionURI());
                                    env = factory.getDefaultEnvelope();
                                    env.getBody().addChild(factory.createOMElement("<xsl:value-of select="$method-name"/>", "<xsl:value-of select="$method-ns"/>", ""));
                                </xsl:when>
                                <xsl:otherwise>
                                    //Unknown style detected !! No code is generated
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:otherwise>
                    </xsl:choose>
        //adding SOAP headers
         _serviceClient.addHeadersToEnvelope(env);
        // create message context with that soap envelope
        org.apache.axis2.context.MessageContext _messageContext = new org.apache.axis2.context.MessageContext() ;
        _messageContext.setEnvelope(env);

        // add the message contxt to the operation client
        _operationClient.addMessageContext(_messageContext);


                    <xsl:choose>
                        <xsl:when test="$outputtype=''">
                            //Nothing to pass as the callback!!!
                        </xsl:when>
                        <xsl:otherwise>
                           _operationClient.setCallback(new org.apache.axis2.client.async.Callback() {
                    public void onComplete(
                            org.apache.axis2.client.async.AsyncResult result) {
                        java.lang.Object object = fromOM(result.getResponseEnvelope().getBody().getFirstElement(),
                               <xsl:value-of select="$outputtype"/>.class,
                               getEnvelopeNamespaces(result.getResponseEnvelope())
                            );
                        callback.receiveResult<xsl:value-of select="@name"/>((<xsl:value-of select="$outputtype"/>) object);
                    }

                    public void onError(java.lang.Exception e) {
                        callback.receiveError<xsl:value-of select="@name"/>(e);
                    }
                });
                        </xsl:otherwise>
                    </xsl:choose>

          org.apache.axis2.util.CallbackReceiver _callbackReceiver = null;
        if ( _operations[<xsl:value-of select="position()-1"/>].getMessageReceiver()==null &amp;&amp;  _operationClient.getOptions().isUseSeparateListener()) {
           _callbackReceiver = new org.apache.axis2.util.CallbackReceiver();
          _operations[<xsl:value-of select="position()-1"/>].setMessageReceiver(
                    _callbackReceiver);
        }

           //execute the operation client
           _operationClient.execute(false);

                    }
                </xsl:if>
                <!-- End of in-out mep -->
            </xsl:if>




            <!-- Start of in only mep-->
            <xsl:if test="$mep='10' or $mep='11'"> <!-- These constants can be found in org.apache.axis2.wsdl.WSDLConstants -->
                <!-- for the in only mep there is no notion of sync or async. And there is no return type also -->
                public void <xsl:text> </xsl:text><xsl:value-of select="@name"/>(
                 <xsl:variable name="inputcount" select="count(input/param[@location='body' and @type!=''])"/>
                    <xsl:choose>
                        <xsl:when test="$inputcount=1">
                            <!-- Even when the parameters are 1 we have to see whether we have the
                          wrapped parameters -->
                            <xsl:variable name="inputWrappedCount" select="count(input/param[@location='body' and @type!='']/param)"/>
                            <xsl:choose>
                                <xsl:when test="$inputWrappedCount &gt; 0">
                                   <xsl:for-each select="input/param[@location='body' and @type!='']/param">
                                        <xsl:if test="position()>1">,</xsl:if><xsl:value-of select="@type"/><xsl:text> </xsl:text><xsl:value-of select="@name"/>
                                    </xsl:for-each>
                                </xsl:when>
                                <xsl:otherwise>
                                    <xsl:value-of select="input/param[@location='body' and @type!='']/@type"/><xsl:text> </xsl:text><xsl:value-of select="input/param[@location='body' and @type!='']/@name"/>
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:when>
                        <xsl:otherwise><!-- Just leave it - nothing we can do here --></xsl:otherwise>
                    </xsl:choose>

                   <xsl:if test="$inputcount=1 and input/param[not(@location='body') and @type!='']">,</xsl:if>
                    <xsl:for-each select="input/param[not(@location='body') and @type!='']">
                        <xsl:if test="position()>1">,</xsl:if><xsl:value-of select="@type"/><xsl:text> </xsl:text><xsl:value-of select="@name"/>
                    </xsl:for-each>

                ) throws java.rmi.RemoteException
                <!--add the faults-->
                <xsl:if test="$mep='11'">
                    <xsl:for-each select="fault/param[@type!='']">
                        ,<xsl:value-of select="@name"/>
                    </xsl:for-each>
                </xsl:if>
                {

                <xsl:if test="$mep='11'">try {</xsl:if>
                org.apache.axis2.client.OperationClient _operationClient = _serviceClient.createClient(_operations[<xsl:value-of select="position()-1"/>].getName());
                _operationClient.getOptions().setAction("<xsl:value-of select="$soapAction"/>");
                _operationClient.getOptions().setExceptionToBeThrownOnSOAPFault(true);

                <xsl:for-each select="input/param[@Action!='']">_operationClient.getOptions().setAction("<xsl:value-of select="@Action"/>");</xsl:for-each>
                org.apache.axiom.soap.SOAPEnvelope env = null;

                <xsl:variable name="count" select="count(input/param[@type!=''])"/>
                                    <xsl:choose>
                                        <!-- test the number of input parameters
                                        If the number of parameter is more then just run the normal test-->
                                        <xsl:when test="$count &gt; 0">
                                            <xsl:choose>
                                                <!-- style being doclit or rpc does not matter -->
                                                <xsl:when test="$style='rpc' or $style='document'">
                                                    //Style is Doc.
                                                    <xsl:variable name="inputcount" select="count(input/param[@location='body' and @type!=''])"/>
                                                    <xsl:choose>
                                                        <xsl:when test="$inputcount=1">
                                                            <!-- Even when the parameters are 1 we have to see whether we have the
                                                                wrapped parameters -->
                                                           <xsl:variable name="inputWrappedCount" select="count(input/param[@location='body' and @type!='']/param)"/>
                                                            <xsl:variable name="inputElementType" select="input/param[@location='body' and @type!='']/@type"></xsl:variable>

                                                            <xsl:choose>
                                                                <xsl:when test="$inputWrappedCount &gt; 0">
                                                                    <xsl:value-of select="$inputElementType"/><xsl:text> </xsl:text>dummyWrappedType = null;
                                                                    env = toEnvelope(getFactory(_operationClient.getOptions().getSoapVersionURI()),
                                                                    <xsl:for-each select="input/param[@location='body' and @type!='']/param">
                                                                        <xsl:value-of select="@name"/>,
                                                                    </xsl:for-each>dummyWrappedType,
                                                                    optimizeContent(new javax.xml.namespace.QName("<xsl:value-of select="$method-ns"/>",
                                                                    "<xsl:value-of select="$method-name"/>")));
                                                                </xsl:when>
                                                                <xsl:otherwise>
                                                                    <!-- there are no unwrapped parameters - go ahead and use the normal wrapped codegen-->
                                                                    env = toEnvelope(getFactory(_operationClient.getOptions().getSoapVersionURI()),
                                                                    <xsl:value-of select="input/param[@location='body' and @type!='']/@name"/>,
                                                                    optimizeContent(new javax.xml.namespace.QName("<xsl:value-of select="$method-ns"/>",
                                                                    "<xsl:value-of select="$method-name"/>")));
                                                                </xsl:otherwise>
                                                            </xsl:choose>
                                                        </xsl:when>
                                                        <xsl:otherwise>
                                                              env = toEnvelope(getFactory(_operationClient.getOptions().getSoapVersionURI()));
                                                        </xsl:otherwise>
                                                  </xsl:choose>

                                                    <xsl:for-each select="input/param[@location='header']">
                                                        // add the children only if the parameter is not null
                                                        if (<xsl:value-of select="@name"/>!=null){
                                                        env.getHeader().addChild(toOM(<xsl:value-of select="@name"/>, optimizeContent(new javax.xml.namespace.QName("<xsl:value-of select="$method-ns"/>", "<xsl:value-of select="$method-name"/>"))));
                                                        }
                                                    </xsl:for-each>
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    //Unknown style detected !! No code is generated
                                                </xsl:otherwise>
                                            </xsl:choose>
                                        </xsl:when>
                                        <!-- No input parameters present. So generate assuming no input parameters-->
                                        <xsl:otherwise>
                                            <xsl:choose>
                                                <xsl:when test="$style='rpc' or $style='document'">
                                                    //Style is taken to be "document". No input parameters
                                                    org.apache.axiom.soap.SOAPFactory factory = getFactory(_operationClient.getOptions().getSoapVersionURI());
                                                    env = factory.getDefaultEnvelope();
                                                    env.getBody().addChild(factory.createOMElement("<xsl:value-of select="$method-name"/>", "<xsl:value-of select="$method-ns"/>", ""));
                                                </xsl:when>
                                                <xsl:otherwise>
                                                     //Unknown style detected !! No code is generated
                                                </xsl:otherwise>
                                            </xsl:choose>
                                        </xsl:otherwise>
                                    </xsl:choose>

              //adding SOAP headers
         _serviceClient.addHeadersToEnvelope(env);
                // create message context with that soap envelope
            org.apache.axis2.context.MessageContext _messageContext = new org.apache.axis2.context.MessageContext() ;
            _messageContext.setEnvelope(env);

            // add the message contxt to the operation client
            _operationClient.addMessageContext(_messageContext);

             _operationClient.execute(true);
           <xsl:if test="$mep='11'">
               }catch(org.apache.axis2.AxisFault f){
                  org.apache.axiom.om.OMElement faultElt = f.getDetail();
                  if (faultElt!=null){
                      if (faultExeptionNameMap.containsKey(faultElt.getQName())){
                          //make the fault by reflection
                          try{
                              java.lang.String exceptionClassName = (java.lang.String)faultExeptionClassNameMap.get(faultElt.getQName());
                              java.lang.Class exceptionClass = java.lang.Class.forName(exceptionClassName);
                              java.lang.Exception ex=
                                      (java.lang.Exception) exceptionClass.newInstance();
                              //message class
                              java.lang.String messageClassName = (java.lang.String)faultMessageMap.get(faultElt.getQName());
                              java.lang.Class messageClass = java.lang.Class.forName(messageClassName);
                              java.lang.Object messageObject = fromOM(faultElt,messageClass,null);
                              java.lang.reflect.Method m = exceptionClass.getMethod("setFaultMessage",
                                         new java.lang.Class[]{messageClass});
                              m.invoke(ex,new java.lang.Object[]{messageObject});
                              <xsl:for-each select="fault/param">
                              if (ex instanceof <xsl:value-of select="@name"/>){
                                throw (<xsl:value-of select="@name"/>)ex;
                              }
                              </xsl:for-each>

                              throw new java.rmi.RemoteException(ex.getMessage(), ex);
                          }catch(java.lang.ClassCastException e){
                             // we cannot intantiate the class - throw the original Axis fault
                              throw f;
                          } catch (java.lang.ClassNotFoundException e) {
                              // we cannot intantiate the class - throw the original Axis fault
                              throw f;
                          }catch (java.lang.NoSuchMethodException e) {
                              // we cannot intantiate the class - throw the original Axis fault
                              throw f;
                          } catch (java.lang.reflect.InvocationTargetException e) {
                              // we cannot intantiate the class - throw the original Axis fault
                              throw f;
                          }  catch (java.lang.IllegalAccessException e) {
                              // we cannot intantiate the class - throw the original Axis fault
                              throw f;
                          }   catch (java.lang.InstantiationException e) {
                              // we cannot intantiate the class - throw the original Axis fault
                              throw f;
                          }
                      }else{
                          throw f;
                      }
                  }else{
                      throw f;
                  }
              }
           </xsl:if>
             return;
           }
            </xsl:if>
          </xsl:if>
        </xsl:for-each>

       /**
        *  A utility method that copies the namepaces from the SOAPEnvelope
        */
       private java.util.Map getEnvelopeNamespaces(org.apache.axiom.soap.SOAPEnvelope env){
        java.util.Map returnMap = new java.util.HashMap();
        java.util.Iterator namespaceIterator = env.getAllDeclaredNamespaces();
        while (namespaceIterator.hasNext()) {
            org.apache.axiom.om.OMNamespace ns = (org.apache.axiom.om.OMNamespace) namespaceIterator.next();
            returnMap.put(ns.getPrefix(),ns.getNamespaceURI());
        }
       return returnMap;
    }

    <xsl:if test="//@policy">
    ////////////////////////////////////////////////////////////////////////
    
    private static org.apache.neethi.Policy getPolicy (java.lang.String policyString) {
    	java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(policyString.getBytes());
    	return org.apache.neethi.PolicyEngine.getPolicy(bais);
    }
    
    /////////////////////////////////////////////////////////////////////////

    </xsl:if>
    
    private javax.xml.namespace.QName[] opNameArray = null;
    private boolean optimizeContent(javax.xml.namespace.QName opName) {
        <xsl:if test="stubMethods">
            setOpNameArray();
        </xsl:if>

        if (opNameArray == null) {
            return false;
        }
        for (int i = 0; i &lt; opNameArray.length; i++) {
            if (opName.equals(opNameArray[i])) {
                return true;   
            }
        }
        return false;
    }
     //<xsl:apply-templates><xsl:with-param name="context">interface-implementation</xsl:with-param></xsl:apply-templates>
   }
   </xsl:template>
</xsl:stylesheet>
