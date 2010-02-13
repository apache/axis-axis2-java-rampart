<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="text"/>

    <!-- cater for the multiple classes - wrappped mode -->
    <xsl:template match="/beans">
        <xsl:variable name="name"><xsl:value-of select="@name"/></xsl:variable>
        /**
        * <xsl:value-of select="$name"/>.java
        *
        * This file was auto-generated from WSDL
        * by the Apache Axis2 version: #axisVersion# #today#
        */

        package <xsl:value-of select="@package"/>;

        /**
        *  <xsl:value-of select="$name"/> wrapped bean classes
        */
        public class <xsl:value-of select="$name"/>{

        <xsl:apply-templates/>

        }
    </xsl:template>

    <!--cater for the multiple classes - unwrappped mode -->
    <xsl:template match="/">
        <xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="bean[not(@helperMode)]">

        <xsl:variable name="name" select="@name"/>
        <xsl:variable name="choice" select="@choice"/>
        <xsl:variable name="simple" select="@simple"/>
        <xsl:variable name="ordered" select="@ordered"/>
        <xsl:variable name="unordered" select="not($ordered)"/>  <!-- for convenience -->
        <xsl:variable name="isType" select="@type"/>
        <xsl:variable name="anon" select="@anon"/>

        <xsl:variable name="nsuri" select="@nsuri"/>
        <xsl:variable name="originalName" select="@originalName"/>
        <xsl:variable name="nsprefix" select="@nsprefix"/>
        <xsl:variable name="extension" select="@extension"/>
        <xsl:variable name="restriction" select="@restriction"/>
        <xsl:variable name="mapperClass" select="@mapperClass"/>
    <!-- write the class header. this should be done only when unwrapped -->

        <xsl:if test="not(not(@unwrapped) or (@skip-write))">
            /**
            * <xsl:value-of select="$name"/>.java
            *
            * This file was auto-generated from WSDL
            * by the Apache Axis2 version: #axisVersion# #today#
            */

            package <xsl:value-of select="@package"/>;
            /**
            *  <xsl:value-of select="$name"/> bean class
            */
        </xsl:if>
        public <xsl:if test="not(@unwrapped) or (@skip-write)">static</xsl:if> class <xsl:value-of select="$name"/> <xsl:if test="$extension"> extends <xsl:value-of select="$extension"/></xsl:if> <xsl:if test="$restriction"> extends <xsl:value-of select="$restriction"/></xsl:if>
        implements org.apache.axis2.databinding.ADBBean{
        <xsl:choose>
            <xsl:when test="@type">/* This type was generated from the piece of schema that had
                name = <xsl:value-of select="$originalName"/>
                Namespace URI = <xsl:value-of select="$nsuri"/>
                Namespace Prefix = <xsl:value-of select="$nsprefix"/>
                */
            </xsl:when>
            <xsl:otherwise>
                public static final javax.xml.namespace.QName MY_QNAME = new javax.xml.namespace.QName(
                "<xsl:value-of select="$nsuri"/>",
                "<xsl:value-of select="$originalName"/>",
                "<xsl:value-of select="$nsprefix"/>");

            </xsl:otherwise>
        </xsl:choose>

        <xsl:if test="$choice">
            /** Whenever a new property is set ensure all others are unset
             *  There can be only one choice and the last one wins
             */
            private void clearAllSettingTrackers() {
            <xsl:for-each select="property">
                local<xsl:value-of select="@javaname"/>Tracker = false;
           </xsl:for-each>
            }
        </xsl:if>


        <xsl:for-each select="property">
            <!-- Write only the NOT inherited properties-->
            <xsl:if test="not(@inherited)">

            <xsl:variable name="propertyType"><xsl:value-of select="@type"></xsl:value-of></xsl:variable>
            <xsl:variable name="propertyName"><xsl:value-of select="@name"></xsl:value-of></xsl:variable>
            <xsl:variable name="javaName"><xsl:value-of select="@javaname"></xsl:value-of></xsl:variable>

            <xsl:variable name="min"><xsl:value-of select="@minOccurs"/></xsl:variable>
            <xsl:variable name="varName">local<xsl:value-of select="$javaName"/></xsl:variable>
            <xsl:variable name="settingTracker">local<xsl:value-of select="$javaName"/>Tracker</xsl:variable>


            <xsl:variable name="lenFacet"><xsl:value-of select="@lenFacet"/></xsl:variable>
               <xsl:variable name="maxLenFacet"><xsl:value-of select="@maxLenFacet"/></xsl:variable>
               <xsl:variable name="minLenFacet"><xsl:value-of select="@minLenFacet"/></xsl:variable>
               <xsl:variable name="maxExFacet"><xsl:value-of select="@maxExFacet"/></xsl:variable>
               <xsl:variable name="minExFacet"><xsl:value-of select="@minExFacet"/></xsl:variable>
               <xsl:variable name="maxInFacet"><xsl:value-of select="@maxInFacet"/></xsl:variable>
               <xsl:variable name="minInFacet"><xsl:value-of select="@minInFacet"/></xsl:variable>
               <xsl:variable name="patternFacet"><xsl:value-of select="@patternFacet"/></xsl:variable>
            <xsl:variable name="shortTypeNameUncapped"  select="@shorttypename"/>
            <xsl:variable name="shortTypeName"
               select="concat(translate( substring($shortTypeNameUncapped, 1, 1 ),'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' ), substring($shortTypeNameUncapped, 2, string-length($shortTypeNameUncapped)))" />


            <xsl:choose>
                <xsl:when test="@removed">

               /**
               * Auto generated getter method
               * Overridden from <xsl:value-of select="$restriction"/>
               *
               * @throws RuntimeException
               */
               public  <xsl:value-of select="$propertyType"/><xsl:text> </xsl:text>get<xsl:value-of select="$javaName"/>(){
                   throw new java.lang.RuntimeException();
               }

               /**
               * Auto generated setter method
               * Overridden from <xsl:value-of select="$restriction"/>
               *
               * @param param <xsl:value-of select="$javaName"/>
               * @throws RuntimeException
               */
               public void set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/> param){
                      throw new java.lang.RuntimeException();
               }

               </xsl:when>
                <xsl:otherwise>
                   <xsl:choose>
                      <xsl:when test="(@restricted) and (@occuranceChanged) and (not(@typeChanged))">
                            <xsl:variable name="basePropertyType"><xsl:value-of select="@arrayBaseType"/></xsl:variable>


                         <!-- generate the validator Method, this is specifiacally for validating the arrays-->
                         /**
                         * Validate the array for <xsl:value-of select="$javaName"/>
                         * Overridden from <xsl:value-of select="$restriction"/>
                         */
                         protected void validate<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/> param){
                         <xsl:if test="not(@unbound)">
                              if ((param != null) &amp;&amp; (param.length &gt; <xsl:value-of select="@maxOccurs"/>)){
                                throw new java.lang.RuntimeException();
                              }
                         </xsl:if>
                         <xsl:if test="$min!=0">
                              if ((param != null) &amp;&amp; (param.length &lt; <xsl:value-of select="$min"/>)){
                                throw new java.lang.RuntimeException();
                              }
                         </xsl:if>
                         }


                         /**
                         * Auto generated setter method
                         * Overridden from <xsl:value-of select="$restriction"/>
                         *
                         * @param param <xsl:value-of select="$javaName"/>
                         */
                         public void set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/> param){
                         <!-- call the validator-->
                                validate<xsl:value-of select="$javaName"/>(param);

                         <xsl:if test="$choice">
                              clearAllSettingTrackers();
                         </xsl:if>
                         <xsl:if test="$min=0 or $choice">
                            <!-- the updating of setting tracker for null values should
                                 happen if the attribute is marked as nillable. Else
                                 the user can set a null value and it is never marked
                                 as set
                            -->
                            <xsl:choose>
                               <xsl:when test="@primitive and not(@array)">
                                   // setting primitive variable always to true
                                   <xsl:value-of select="$settingTracker"/> = true;
                               </xsl:when>
                               <xsl:otherwise>
                                   if (param != null){
                                      //update the setting tracker
                                      <xsl:value-of select="$settingTracker"/> = true;
                                   } else {
                                      <xsl:choose>
                                          <xsl:when test="@nillable">
                                              <xsl:value-of select="$settingTracker"/> = true;
                                          </xsl:when>
                                          <xsl:otherwise>
                                              <xsl:value-of select="$settingTracker"/> = false;
                                          </xsl:otherwise>
                                      </xsl:choose>
                                   }
                               </xsl:otherwise>
                            </xsl:choose>
                         </xsl:if>
                              this.<xsl:value-of select="$varName"/>=param;
                         }
                      </xsl:when>
                      <xsl:otherwise>

                        /**
                        * field for <xsl:value-of select="$javaName"/>
                        <xsl:if test="@attribute">
                        * This was an Attribute!</xsl:if>
                        <xsl:if test="@array">
                        * This was an Array!</xsl:if>
                        <xsl:if test="@typeChanged">
                        * Type of this field is a subtype of its original.</xsl:if>
                        <xsl:if test="(@rewrite) and (@occuranceChanged)">
                        * This field was an array in <xsl:value-of select="$restriction"/>.</xsl:if>
                        */

                        protected <xsl:value-of select="$propertyType"/><xsl:text> </xsl:text><xsl:value-of select="$varName" /> ;
                        <xsl:if test="enumFacet">
                        private static java.util.HashMap _table_ = new java.util.HashMap();

                        // Constructor
                        protected <xsl:value-of select="$name"/>(<xsl:value-of select="$propertyType"/> value) {
                            <xsl:value-of select="$varName" /> = value;
                            <xsl:choose>
                                       <xsl:when test="@primitive">
                                         _table_.put(<xsl:value-of select="$varName" /> + "", this);
                                       </xsl:when>
                                       <xsl:otherwise>
                                           _table_.put(<xsl:value-of select="$varName" />, this);
                                       </xsl:otherwise>
                                   </xsl:choose>

                        }

                        <xsl:for-each select="enumFacet">
                            public static final <xsl:value-of select="$propertyType"/> _<xsl:value-of select="@id"/> =
                                org.apache.axis2.databinding.utils.ConverterUtil.convertTo<xsl:value-of select="$shortTypeName"/>("<xsl:value-of select="@value"/>");
                        </xsl:for-each>
                        <xsl:for-each select="enumFacet">
                            public static final <xsl:value-of select="$name"/><xsl:text> </xsl:text><xsl:value-of select="@id"/> =
                                new <xsl:value-of select="$name"/>(_<xsl:value-of select="@id"/>);
                        </xsl:for-each>

                            public <xsl:value-of select="$propertyType"/> getValue() { return <xsl:value-of select="$varName" />;}
                            public static <xsl:value-of select="$name"/> fromValue(<xsl:value-of select="$propertyType"/> value)
                                  throws java.lang.IllegalArgumentException {
                                <xsl:value-of select="$name"/> enumeration = (<xsl:value-of select="$name"/>)
                            <xsl:choose>
                                       <xsl:when test="@primitive">
                                         _table_.get(value + "");
                                       </xsl:when>
                                       <xsl:otherwise>
                                           _table_.get(value);
                                       </xsl:otherwise>
                                   </xsl:choose>

                                if (enumeration==null) throw new java.lang.IllegalArgumentException();
                                return enumeration;
                            }
                            public static <xsl:value-of select="$name"/> fromString(java.lang.String value)
                                  throws java.lang.IllegalArgumentException {
                                try {
                                   <xsl:choose>
                                       <xsl:when test="@primitive">
                                         return fromValue(org.apache.axis2.databinding.utils.ConverterUtil.convertTo<xsl:value-of select="$shortTypeName"/>(value));
                                       </xsl:when>
                                       <xsl:otherwise>
                                           return fromValue(new <xsl:value-of select="$propertyType"/>(value));
                                       </xsl:otherwise>
                                   </xsl:choose>

                                } catch (java.lang.Exception e) {
                                    throw new java.lang.IllegalArgumentException();
                                }
                            }
                            public boolean equals(java.lang.Object obj) {return (obj == this);}
                            public int hashCode() { return toString().hashCode();}
                            public java.lang.String toString() {
                            <xsl:choose>
                                <xsl:when test="@primitive">
                                    return <xsl:value-of select="$varName"/> + "";
                                </xsl:when>
                                <xsl:otherwise>
                                    return <xsl:value-of select="$varName"/>.toString();
                                </xsl:otherwise>
                            </xsl:choose>

                            }

                        </xsl:if>
                        <xsl:if test="not(enumFacet)">
                        <!-- Generate a tracker only if the min occurs is zero, which means if the user does
                           not bother to set that value, we do not send it -->
                           <xsl:if test="$min=0 or $choice">
                           /*  This tracker boolean wil be used to detect whether the user called the set method
                          *   for this attribute. It will be used to determine whether to include this field
                           *   in the serialized XML
                           */
                           protected boolean <xsl:value-of select="$settingTracker"/> = false ;
                           </xsl:if>

                           /**
                           * Auto generated getter method
                           * @return <xsl:value-of select="$propertyType"/>
                           */
                           public  <xsl:value-of select="$propertyType"/><xsl:text> </xsl:text>get<xsl:value-of select="$javaName"/>(){
                               return <xsl:value-of select="$varName"/>;
                           }

                           <!-- When generating the setters, we have to cater differently for the array!-->
                        <xsl:choose>
                               <xsl:when test="@array">
                               <xsl:variable name="basePropertyType"><xsl:value-of select="@arrayBaseType"/></xsl:variable>


                               <!-- generate the validator Method, this is specifiacally for validating the arrays-->
                              /**
                               * validate the array for <xsl:value-of select="$javaName"/>
                               */
                              protected void validate<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/> param){
                             <xsl:if test="not(@unbound)">
                              if ((param != null) &amp;&amp; (param.length &gt; <xsl:value-of select="@maxOccurs"/>)){
                                throw new java.lang.RuntimeException();
                              }
                              </xsl:if>
                              <xsl:if test="$min!=0">
                              if ((param != null) &amp;&amp; (param.length &lt; <xsl:value-of select="$min"/>)){
                                throw new java.lang.RuntimeException();
                              }
                              </xsl:if>
                              }


                             /**
                              * Auto generated setter method
                              * @param param <xsl:value-of select="$javaName"/>
                              */
                              public void set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/> param){
                              <!-- call the validator-->
                                   validate<xsl:value-of select="$javaName"/>(param);

                               <xsl:if test="$choice">
                                   clearAllSettingTrackers();
                               </xsl:if>
                               <xsl:if test="$min=0 or $choice">
                                   <!-- the updating of setting tracker for null values should
                                     happen if the attribute is marked as nillable. Else
                                     the user can set a null value and it is never marked
                                     as set
                                   -->
                                  <xsl:choose>
                                      <xsl:when test="@primitive and not(@array)">
                                          // setting the primitive attribute to true
                                          <xsl:value-of select="$settingTracker"/> = true;
                                      </xsl:when>
                                      <xsl:otherwise>
                                          if (param != null){
                                             //update the setting tracker
                                             <xsl:value-of select="$settingTracker"/> = true;
                                          } else {
                                             <xsl:choose>
                                                 <xsl:when test="@nillable">
                                                     <xsl:value-of select="$settingTracker"/> = true;
                                                 </xsl:when>
                                                 <xsl:otherwise>
                                                     <xsl:value-of select="$settingTracker"/> = false;
                                                 </xsl:otherwise>
                                             </xsl:choose>
                                          }
                                      </xsl:otherwise>
                                   </xsl:choose>

                               </xsl:if>
                                      this.<xsl:value-of select="$varName"/>=param;
                              }

                               <!--

                               we special case the 'array' scenario and generate a
                               convenience method for adding elements one by one to
                               the array. The current implementation is somewhat
                               inefficient but gets the job done.Since a primitive
                               cannot be treated as an object it has to be ignored!

                             -->
                             <xsl:if test="not(@primitive)">
                             /**
                             * Auto generated add method for the array for convenience
                             * @param param <xsl:value-of select="$basePropertyType"/>
                             */
                             public void add<xsl:value-of select="$javaName"/>(<xsl:value-of select="$basePropertyType"/> param){
                                   if (<xsl:value-of select="$varName"/> == null){
                                   <xsl:value-of select="$varName"/> = new <xsl:value-of select="$propertyType"/>{};
                                   }

                            <xsl:if test="$choice">
                                   clearAllSettingTrackers();
                            </xsl:if>
                            <xsl:if test="$min=0 or $choice">
                                 //update the setting tracker
                                <xsl:value-of select="$settingTracker"/> = true;
                            </xsl:if>

                               java.util.List list =
                            org.apache.axis2.databinding.utils.ConverterUtil.toList(<xsl:value-of select="$varName"/>);
                               list.add(param);
                               this.<xsl:value-of select="$varName"/> =
                             (<xsl:value-of select="$propertyType"/>)list.toArray(
                            new <xsl:value-of select="$basePropertyType"/>[list.size()]);

                             }
                             </xsl:if>
                             <!-- end of special casing for the array-->

                               </xsl:when>
                            <!-- Non array setter method-->
                            <xsl:otherwise>
                            /**
                               * Auto generated setter method
                               * @param param <xsl:value-of select="$javaName"/>
                               */
                               public void set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/> param){
                            <xsl:if test="$choice">
                                clearAllSettingTrackers();
                            </xsl:if>
                            <xsl:if test="$min=0 or $choice">
                                <xsl:choose>
                                   <xsl:when test="@primitive and not(@array)">
                                       // setting primitive attribute tracker to true
                                       <xsl:value-of select="$settingTracker"/> = true;
                                   </xsl:when>
                                   <xsl:otherwise>
                                       if (param != null){
                                          //update the setting tracker
                                          <xsl:value-of select="$settingTracker"/> = true;
                                       } else {
                                          <xsl:choose>
                                              <xsl:when test="@nillable">
                                                  <xsl:value-of select="$settingTracker"/> = true;
                                              </xsl:when>
                                              <xsl:otherwise>
                                                  <xsl:value-of select="$settingTracker"/> = false;
                                              </xsl:otherwise>
                                          </xsl:choose>
                                       }
                                   </xsl:otherwise>
                                </xsl:choose>
                            </xsl:if>

                               <xsl:choose>
                            <xsl:when test="(@restrictionBaseType)">
                               <xsl:choose>
                                <xsl:when test="(@patternFacet)">
                                    if ( param.matches( "<xsl:value-of select="$patternFacet"/>" )) {
                                        this.<xsl:value-of select="$varName"/>=param;
                                    }
                                    else {
                                        throw new java.lang.RuntimeException();
                                    }
                                </xsl:when>
                                <xsl:when test="(@lenFacet)">
                                    if ( param.length() == <xsl:value-of select="@lenFacet"/> ) {
                                        this.<xsl:value-of select="$varName"/>=param;
                                    }
                                    else {
                                        throw new java.lang.RuntimeException();
                                    }
                                </xsl:when>
                                <xsl:when test="(@maxLenFacet) or (@minLenFacet)">
                                    if ( <xsl:if test="(@minLenFacet)"> <xsl:value-of select="$minLenFacet"/> &lt; </xsl:if> param.length() <xsl:if test="(@maxLenFacet)"> &gt; <xsl:value-of select="$maxLenFacet"/> = </xsl:if> ) {
                                        this.<xsl:value-of select="$varName"/>=param;
                                    }
                                    else {
                                        throw new java.lang.RuntimeException();
                                    }
                                </xsl:when>
                                <xsl:when test="(@maxExFacet) or (@minExFacet) or (@maxInFacet) or (@minInFacet)">
                                    if ( <xsl:if test="(@minExFacet)"> <xsl:value-of select="$minExFacet"/> &lt; </xsl:if> <xsl:if test="(@minInFacet)"> <xsl:value-of select="$minInFacet"/> &lt;= </xsl:if> param <xsl:if test="(@maxExFacet)"> &gt; <xsl:value-of select="$maxExFacet"/> </xsl:if> <xsl:if test="(@maxInFacet)"> &gt;= <xsl:value-of select="$maxInFacet"/> </xsl:if> ) {

                                        this.<xsl:value-of select="$varName"/>=param;
                                    }
                                    else {
                                        throw new java.lang.RuntimeException();
                                    }
                                </xsl:when>
                                <xsl:otherwise>
                                     this.<xsl:value-of select="$varName"/>=param;
                                </xsl:otherwise>
                            </xsl:choose>
                            </xsl:when>

                            <xsl:otherwise>
                                    this.<xsl:value-of select="$varName"/>=param;
                            </xsl:otherwise>
                            </xsl:choose>

                               }
                            </xsl:otherwise>
                        </xsl:choose>
                        </xsl:if>

                      </xsl:otherwise>
                   </xsl:choose>

                </xsl:otherwise>
            </xsl:choose>

             <!-- end of xsl:if for not(@inherited) -->
            </xsl:if>

        </xsl:for-each>

     /**
     * isReaderMTOMAware
     * @return true if the reader supports MTOM
     */
   public static boolean isReaderMTOMAware(javax.xml.stream.XMLStreamReader reader) {
        boolean isReaderMTOMAware = false;
        <!-- workaround for the issues in the wstx reader!-->
        try{
          isReaderMTOMAware = java.lang.Boolean.TRUE.equals(reader.getProperty(org.apache.axiom.om.OMConstants.IS_DATA_HANDLERS_AWARE));
        }catch(java.lang.IllegalArgumentException e){
          isReaderMTOMAware = false;
        }
        return isReaderMTOMAware;
   }
     <!-- ######################################################################################### -->
     <!-- get OMElement methods that allows direct writing -->
        /**
        *
        * @param parentQName
        * @param factory
        * @return org.apache.axiom.om.OMElement
        */
       public org.apache.axiom.om.OMElement getOMElement(
               final javax.xml.namespace.QName parentQName,
               final org.apache.axiom.om.OMFactory factory){

        org.apache.axiom.om.OMDataSource dataSource = getOMDataSource(parentQName, factory);

        <xsl:choose>
            <xsl:when test="@type">
               return new org.apache.axiom.om.impl.llom.OMSourcedElementImpl(
               parentQName,factory,dataSource);
            </xsl:when>
            <xsl:otherwise>
               return new org.apache.axiom.om.impl.llom.OMSourcedElementImpl(
               MY_QNAME,factory,dataSource);
            </xsl:otherwise>
       </xsl:choose>
       }

     /**
     *
     * @param parentQName
     * @param factory
     * @return org.apache.axiom.om.OMElement
     */
    public org.apache.axiom.om.OMDataSource getOMDataSource(
            final javax.xml.namespace.QName parentQName,
            final org.apache.axiom.om.OMFactory factory){


        org.apache.axiom.om.OMDataSource dataSource =
                       new org.apache.axis2.databinding.ADBDataSource(this,parentQName){

         public void serialize(
                                  javax.xml.stream.XMLStreamWriter xmlWriter) throws javax.xml.stream.XMLStreamException {
            <xsl:choose>
            <xsl:when test="@type or @anon">
                <!-- For a type write the passed in QName first-->

                java.lang.String prefix = parentQName.getPrefix();
                java.lang.String namespace = parentQName.getNamespaceURI();

                if (namespace != null) {
                    java.lang.String writerPrefix = xmlWriter.getPrefix(namespace);
                    if (writerPrefix != null) {
                        xmlWriter.writeStartElement(namespace, parentQName.getLocalPart());
                    } else {
                        if (prefix == null) {
                            prefix = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();
                        }

                        xmlWriter.writeStartElement(prefix, parentQName.getLocalPart(), namespace);
                        xmlWriter.writeNamespace(prefix, namespace);
                        xmlWriter.setPrefix(prefix, namespace);
                    }
                } else {
                    xmlWriter.writeStartElement(parentQName.getLocalPart());
                }

                <!-- write the type attribute if needed -->
               <xsl:if test="$extension">
               writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","type",
                       registerPrefix(xmlWriter,"<xsl:value-of select="$nsuri"/>")+":<xsl:value-of select="$originalName"/>",
                       xmlWriter);
               </xsl:if>
                <!--First serialize the attributes!-->
                <xsl:for-each select="property[@attribute]">
                    <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                    <xsl:variable name="varName">local<xsl:value-of select="@javaname"/></xsl:variable>
                     <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                    <xsl:choose>
                        <!-- Note - It is assumed that any attributes are OMAttributes-->
                        <xsl:when test="@any and not(@array)">
                           writeAttribute(<xsl:value-of select="$varName"/>.getNamespace().getName(),
                                                     <xsl:value-of select="$varName"/>.getLocalName(),
                                                     <xsl:value-of select="$varName"/>.getAttributeValue(),
                                                     xmlWriter);
                        </xsl:when>
                        <xsl:when test="@any and @array">
                             if (<xsl:value-of select="$varName"/> != null) {
                                 for (int i=0;i &lt;<xsl:value-of select="$varName"/>.length;i++){
                                     writeAttribute(<xsl:value-of select="$varName"/>[i].getNamespace().getName(),
                                                    <xsl:value-of select="$varName"/>[i].getLocalName(),
                                                    <xsl:value-of select="$varName"/>[i].getAttributeValue(),xmlWriter);
                                     }
                             }
                        </xsl:when>
                        <!-- there can never be attribute arrays in the normal case-->
                        <xsl:when test="@optional">
                             // optional attribute <xsl:value-of select="$propertyName"/>
                             try {
                                writeAttribute("<xsl:value-of select="$namespace"/>",
                                               "<xsl:value-of select="$propertyName"/>",
                                               org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>), xmlWriter);
                            } catch (NullPointerException e) {
                                // If <xsl:value-of select="$varName"/> was null
                                // it can not be serialized.
                            }
                        </xsl:when>
                        <xsl:otherwise>
                             writeAttribute("<xsl:value-of select="$namespace"/>",
                                                     "<xsl:value-of select="$propertyName"/>",
                                                      org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>),
                            xmlWriter);
                        </xsl:otherwise>
                    </xsl:choose>
                </xsl:for-each>

                <!-- Now serialize the elements-->
                <xsl:for-each select="property[not(@attribute)]">
                    <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                    <xsl:variable name="varName">local<xsl:value-of select="@javaname"/></xsl:variable>
                    <xsl:variable name="min"><xsl:value-of select="@minOccurs"/></xsl:variable>
                    <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                    <xsl:variable name="settingTracker">local<xsl:value-of select="@javaname"/>Tracker</xsl:variable>

                    <xsl:variable name="propertyType"><xsl:value-of select="@type"/></xsl:variable>

                    <xsl:if test="$min=0 or $choice"> if (<xsl:value-of select="$settingTracker"/>){</xsl:if>
                    <xsl:choose>
                        <xsl:when test="@ours and not(@array) and not(@default)">
                            <xsl:choose>
                                <xsl:when test="@nillable">
                                    if (<xsl:value-of select="$varName"/>==null){

                                            java.lang.String namespace2 = "<xsl:value-of select="$namespace"/>";

                                        if (! namespace2.equals("")) {
                                            java.lang.String prefix2 = xmlWriter.getPrefix(namespace2);

                                            if (prefix2 == null) {
                                                prefix2 = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                xmlWriter.writeStartElement(prefix2,"<xsl:value-of select="$propertyName"/>", namespace2);
                                                xmlWriter.writeNamespace(prefix2, namespace2);
                                                xmlWriter.setPrefix(prefix2, namespace2);

                                            } else {
                                                xmlWriter.writeStartElement(namespace2,"<xsl:value-of select="$propertyName"/>");
                                            }

                                        } else {
                                            xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                        }


                                       // write the nil attribute
                                      writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                      xmlWriter.writeEndElement();
                                    }else{
                                     <xsl:value-of select="$varName"/>.getOMDataSource(
                                       new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>"),
                                        factory).serialize(xmlWriter);
                                    }
                                </xsl:when>
                                <xsl:otherwise>
                                    if (<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }
                                   <xsl:value-of select="$varName"/>.getOMDataSource(
                                       new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>"),
                                       factory).serialize(xmlWriter);
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:when>
                        <xsl:when test="@ours and @array and not(@default)">
                             if (<xsl:value-of select="$varName"/>!=null){
                                    for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                                        if (<xsl:value-of select="$varName"/>[i] != null){
                                         <xsl:value-of select="$varName"/>[i].getOMDataSource(
                                                   new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>"),
                                                   factory).serialize(xmlWriter);
                                        } else {
                                           <xsl:choose>
                                            <xsl:when test="@nillable">
                                                    // write null attribute
                                                    java.lang.String namespace2 = "<xsl:value-of select="$namespace"/>";
                                                    if (! namespace2.equals("")) {
                                                        java.lang.String prefix2 = xmlWriter.getPrefix(namespace2);

                                                        if (prefix2 == null) {
                                                            prefix2 = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                            xmlWriter.writeStartElement(prefix2,"<xsl:value-of select="$propertyName"/>", namespace2);
                                                            xmlWriter.writeNamespace(prefix2, namespace2);
                                                            xmlWriter.setPrefix(prefix2, namespace2);

                                                        } else {
                                                            xmlWriter.writeStartElement(namespace2,"<xsl:value-of select="$propertyName"/>");
                                                        }

                                                    } else {
                                                        xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                                    }

                                                   // write the nil attribute
                                                   writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                                   xmlWriter.writeEndElement();
                                            </xsl:when>
                                            <xsl:when test="$min=0">
                                                // we don't have to do any thing since minOccures is zero
                                            </xsl:when>
                                            <xsl:otherwise>
                                                   throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                            </xsl:otherwise>
                                        </xsl:choose>
                                        }

                                    }
                             } else {
                                <xsl:choose>
                                <xsl:when test="@nillable">
                                        // write null attribute
                                        java.lang.String namespace2 = "<xsl:value-of select="$namespace"/>";
                                        if (! namespace2.equals("")) {
                                            java.lang.String prefix2 = xmlWriter.getPrefix(namespace2);

                                            if (prefix2 == null) {
                                                prefix2 = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                xmlWriter.writeStartElement(prefix2,"<xsl:value-of select="$propertyName"/>", namespace2);
                                                xmlWriter.writeNamespace(prefix2, namespace2);
                                                xmlWriter.setPrefix(prefix2, namespace2);

                                            } else {
                                                xmlWriter.writeStartElement(namespace2,"<xsl:value-of select="$propertyName"/>");
                                            }

                                        } else {
                                            xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                        }

                                       // write the nil attribute
                                       writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                       xmlWriter.writeEndElement();
                                </xsl:when>
                                <xsl:otherwise>
                                       throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                </xsl:otherwise>
                            </xsl:choose>
                            }
                        </xsl:when>

                        <xsl:when test="@default and @array">
                            <!-- Note - Assumed to be OMElement-->
                            if (<xsl:value-of select="$varName"/>!=null){
                                 for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                                    if (<xsl:value-of select="$varName"/>[i] != null){
                                           // write null attribute
                                            java.lang.String namespace2 = "<xsl:value-of select="$namespace"/>";
                                            if (! namespace2.equals("")) {
                                                java.lang.String prefix2 = xmlWriter.getPrefix(namespace2);

                                                if (prefix2 == null) {
                                                    prefix2 = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                    xmlWriter.writeStartElement(prefix2,"<xsl:value-of select="$propertyName"/>", namespace2);
                                                    xmlWriter.writeNamespace(prefix2, namespace2);
                                                    xmlWriter.setPrefix(prefix2, namespace2);

                                                } else {
                                                    xmlWriter.writeStartElement(namespace2,"<xsl:value-of select="$propertyName"/>");
                                                }

                                            } else {
                                                xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                            }
                                            <xsl:value-of select="$varName"/>[i].serialize(xmlWriter);
                                            xmlWriter.writeEndElement();
                                    } else {
                                       <xsl:choose>
                                       <xsl:when test="@nillable">
                                            // write null attribute
                                            java.lang.String namespace2 = "<xsl:value-of select="$namespace"/>";
                                            if (! namespace2.equals("")) {
                                                java.lang.String prefix2 = xmlWriter.getPrefix(namespace2);

                                                if (prefix2 == null) {
                                                    prefix2 = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                    xmlWriter.writeStartElement(prefix2,"<xsl:value-of select="$propertyName"/>", namespace2);
                                                    xmlWriter.writeNamespace(prefix2, namespace2);
                                                    xmlWriter.setPrefix(prefix2, namespace2);

                                                } else {
                                                    xmlWriter.writeStartElement(namespace2,"<xsl:value-of select="$propertyName"/>");
                                                }

                                            } else {
                                                xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                            }

                                           // write the nil attribute
                                           writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                           xmlWriter.writeEndElement();
                                        </xsl:when>
                                        <xsl:when test="$min=0">
                                              // we have to do nothing since minOccurs is zero
                                        </xsl:when>
                                        <xsl:otherwise>
                                             throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                        </xsl:otherwise>
                                    </xsl:choose>
                                    }
                                 }
                            } else {
                                 <xsl:choose>
                                   <xsl:when test="@nillable">
                                        // write null attribute
                                        java.lang.String namespace2 = "<xsl:value-of select="$namespace"/>";
                                        if (! namespace2.equals("")) {
                                            java.lang.String prefix2 = xmlWriter.getPrefix(namespace2);

                                            if (prefix2 == null) {
                                                prefix2 = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                xmlWriter.writeStartElement(prefix2,"<xsl:value-of select="$propertyName"/>", namespace2);
                                                xmlWriter.writeNamespace(prefix2, namespace2);
                                                xmlWriter.setPrefix(prefix2, namespace2);

                                            } else {
                                                xmlWriter.writeStartElement(namespace2,"<xsl:value-of select="$propertyName"/>");
                                            }

                                        } else {
                                            xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                        }

                                       // write the nil attribute
                                       writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                       xmlWriter.writeEndElement();
                                    </xsl:when>
                                    <xsl:otherwise>
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    </xsl:otherwise>
                                </xsl:choose>
                            }

                        </xsl:when>

                        <xsl:when test="@default and not(@array)">
                            <!-- Note - Assumed to be OMElement-->
                            if (<xsl:value-of select="$varName"/>!=null){
                                // write null attribute
                                java.lang.String namespace2 = "<xsl:value-of select="$namespace"/>";
                                if (! namespace2.equals("")) {
                                    java.lang.String prefix2 = xmlWriter.getPrefix(namespace2);

                                    if (prefix2 == null) {
                                        prefix2 = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                        xmlWriter.writeStartElement(prefix2,"<xsl:value-of select="$propertyName"/>", namespace2);
                                        xmlWriter.writeNamespace(prefix2, namespace2);
                                        xmlWriter.setPrefix(prefix2, namespace2);

                                    } else {
                                        xmlWriter.writeStartElement(namespace2,"<xsl:value-of select="$propertyName"/>");
                                    }

                                } else {
                                    xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                }
                                <xsl:value-of select="$varName"/>.serialize(xmlWriter);
                                xmlWriter.writeEndElement();
                            } else {
                                <xsl:choose>
                                 <xsl:when test="@nillable">
                                        // write null attribute
                                            java.lang.String namespace2 = "<xsl:value-of select="$namespace"/>";
                                            if (! namespace2.equals("")) {
                                                java.lang.String prefix2 = xmlWriter.getPrefix(namespace2);

                                                if (prefix2 == null) {
                                                    prefix2 = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                    xmlWriter.writeStartElement(prefix2,"<xsl:value-of select="$propertyName"/>", namespace2);
                                                    xmlWriter.writeNamespace(prefix2, namespace2);
                                                    xmlWriter.setPrefix(prefix2, namespace2);

                                                } else {
                                                    xmlWriter.writeStartElement(namespace2,"<xsl:value-of select="$propertyName"/>");
                                                }

                                            } else {
                                                xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                            }

                                           // write the nil attribute
                                           writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                           xmlWriter.writeEndElement();
                                    </xsl:when>
                                    <xsl:otherwise>
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    </xsl:otherwise>
                                 </xsl:choose>
                            }


                        </xsl:when>
                        <!-- handle non ADB arrays - Not any however -->
                        <xsl:when test="@array and not(@any)">
                             if (<xsl:value-of select="$varName"/>!=null) {
                                   for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                                        <xsl:if test="@primitive">
                                            namespace = "<xsl:value-of select="$namespace"/>";
                                            if (! namespace.equals("")) {
                                                prefix = xmlWriter.getPrefix(namespace);

                                                if (prefix == null) {
                                                    prefix = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                    xmlWriter.writeStartElement(prefix,"<xsl:value-of select="$propertyName"/>", namespace);
                                                    xmlWriter.writeNamespace(prefix, namespace);
                                                    xmlWriter.setPrefix(prefix, namespace);

                                                } else {
                                                    xmlWriter.writeStartElement(namespace,"<xsl:value-of select="$propertyName"/>");
                                                }

                                            } else {
                                                xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                            }
                                            xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>[i]));
                                            xmlWriter.writeEndElement();

                                        </xsl:if>
                                        <xsl:if test="not(@primitive)">
                                            if (<xsl:value-of select="$varName"/>[i] != null){
                                                namespace = "<xsl:value-of select="$namespace"/>";
                                                if (! namespace.equals("")) {
                                                    prefix = xmlWriter.getPrefix(namespace);

                                                    if (prefix == null) {
                                                        prefix = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                        xmlWriter.writeStartElement(prefix,"<xsl:value-of select="$propertyName"/>", namespace);
                                                        xmlWriter.writeNamespace(prefix, namespace);
                                                        xmlWriter.setPrefix(prefix, namespace);

                                                    } else {
                                                        xmlWriter.writeStartElement(namespace,"<xsl:value-of select="$propertyName"/>");
                                                    }

                                                } else {
                                                    xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                                }
                                            <xsl:choose>
                                                <xsl:when test="$propertyType='java.lang.String[]'">
                                                    xmlWriter.writeCharacters(<xsl:value-of select="$varName"/>[i]);
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>[i]));
                                                </xsl:otherwise>
                                            </xsl:choose>
                                                xmlWriter.writeEndElement();

                                            } else {
                                               <xsl:choose>
                                                   <xsl:when test="@nillable">
                                                       // write null attribute
                                                        namespace = "<xsl:value-of select="$namespace"/>";
                                                        if (! namespace.equals("")) {
                                                            prefix = xmlWriter.getPrefix(namespace);

                                                            if (prefix == null) {
                                                                prefix = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                                xmlWriter.writeStartElement(prefix,"<xsl:value-of select="$propertyName"/>", namespace);
                                                                xmlWriter.writeNamespace(prefix, namespace);
                                                                xmlWriter.setPrefix(prefix, namespace);

                                                            } else {
                                                                xmlWriter.writeStartElement(namespace,"<xsl:value-of select="$propertyName"/>");
                                                            }

                                                        } else {
                                                            xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                                        }
                                                        writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                                        xmlWriter.writeEndElement();
                                                   </xsl:when>
                                                   <xsl:when test="$min=0">
                                                       // we have to do nothing since minOccurs is zero
                                                   </xsl:when>
                                                   <xsl:otherwise>
                                                       throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                                   </xsl:otherwise>

                                               </xsl:choose>
                                            }
                                        </xsl:if>
                                   }
                             } else {
                                 <xsl:choose>
                                    <xsl:when test="@nillable">
                                         // write the null attribute
                                        // write null attribute
                                            java.lang.String namespace2 = "<xsl:value-of select="$namespace"/>";
                                            if (! namespace2.equals("")) {
                                                java.lang.String prefix2 = xmlWriter.getPrefix(namespace2);

                                                if (prefix2 == null) {
                                                    prefix2 = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                    xmlWriter.writeStartElement(prefix2,"<xsl:value-of select="$propertyName"/>", namespace2);
                                                    xmlWriter.writeNamespace(prefix2, namespace2);
                                                    xmlWriter.setPrefix(prefix2, namespace2);

                                                } else {
                                                    xmlWriter.writeStartElement(namespace2,"<xsl:value-of select="$propertyName"/>");
                                                }

                                            } else {
                                                xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                            }

                                           // write the nil attribute
                                           writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                           xmlWriter.writeEndElement();
                                    </xsl:when>
                                    <xsl:otherwise>
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    </xsl:otherwise>
                                </xsl:choose>
                             }

                        </xsl:when>

                         <!-- handle non ADB arrays  - Any case  - any may not be
                         nillable -->
                        <xsl:when test="@array and @any">
                            <!-- Note - Assumed to be OMElement-->
                            if (<xsl:value-of select="$varName"/> != null){
                                for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                                    if (<xsl:value-of select="$varName"/>[i] != null){
                                        <xsl:value-of select="$varName"/>[i].serialize(xmlWriter);
                                    } else {
                                        <xsl:choose>
                                            <xsl:when test="$min=0">
                                                // we have to do nothing since minOccures zero
                                            </xsl:when>
                                            <xsl:otherwise>
                                               throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    }
                                }
                            } else {
                                throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                            }
                        </xsl:when>
                        <!-- handle any - non array case-->
                         <xsl:when test="@any">
                            <!-- Note - Assumed to be OMElement-->
                            if (<xsl:value-of select="$varName"/> != null) {
                                <xsl:value-of select="$varName"/>.serialize(xmlWriter);
                            } else {
                               throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                            }
                        </xsl:when>
                        <!-- handle all other cases -->
                         <xsl:otherwise>
                                <xsl:if test="not($simple)">
                                    namespace = "<xsl:value-of select="$namespace"/>";
                                    if (! namespace.equals("")) {
                                        prefix = xmlWriter.getPrefix(namespace);

                                        if (prefix == null) {
                                            prefix = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                            xmlWriter.writeStartElement(prefix,"<xsl:value-of select="$propertyName"/>", namespace);
                                            xmlWriter.writeNamespace(prefix, namespace);
                                            xmlWriter.setPrefix(prefix, namespace);

                                        } else {
                                            xmlWriter.writeStartElement(namespace,"<xsl:value-of select="$propertyName"/>");
                                        }

                                    } else {
                                        xmlWriter.writeStartElement("<xsl:value-of select="$propertyName"/>");
                                    }
                                </xsl:if>
                             <xsl:choose>
                                 <!-- handle the binary case -->
                                 <xsl:when test="@binary">

                                        <!-- Handling the null byte array -->
                                    if (<xsl:value-of select="$varName"/>!=null)
                                    {
                                        org.apache.axiom.om.impl.llom.OMTextImpl <xsl:value-of select="$varName"/>_binary = new  org.apache.axiom.om.impl.llom.OMTextImpl( <xsl:value-of select="$varName"/>, org.apache.axiom.om.OMAbstractFactory.getOMFactory());
                                        <xsl:value-of select="$varName"/>_binary.internalSerializeAndConsume(xmlWriter);
                                    }

                                 </xsl:when>
                                 <xsl:otherwise>
                                    <xsl:if test="not(@primitive)">

                                          if (<xsl:value-of select="$varName"/>==null){
                                              // write the nil attribute
                                              <xsl:choose>
                                                  <xsl:when test="@nillable">
                                                     writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                                  </xsl:when>
                                                  <xsl:otherwise>
                                                     throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                                  </xsl:otherwise>
                                              </xsl:choose>
                                          }else{

                                        <xsl:choose>
                                            <xsl:when test="$propertyType='javax.xml.namespace.QName'">
                                                        java.lang.String namespaceURI =<xsl:value-of select="$varName"/>.getNamespaceURI();
                                                        if(namespaceURI !=null){
                                                           prefix = <xsl:value-of select="$varName"/>.getPrefix();
                                                           if (prefix == null) {
                                                            prefix = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();
                                                          }
                                                         xmlWriter.writeNamespace(prefix,namespaceURI );
                                                         xmlWriter.writeCharacters(prefix + ":"+ org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                                                        } else {
                                                           xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                                                        }
                                            </xsl:when>
                                            <xsl:when test="$propertyType='org.apache.axiom.om.OMElement'">
                                                <xsl:value-of select="$varName"/>.serialize(xmlWriter);
                                            </xsl:when>
                                            <xsl:when test="$propertyType='java.lang.String'">
                                                   xmlWriter.writeCharacters(<xsl:value-of select="$varName"/>);
                                            </xsl:when>
                                            <xsl:otherwise>
                                                   xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                                            </xsl:otherwise>
                                        </xsl:choose>
                                          }
                                    </xsl:if>
                                    <xsl:if test="@primitive">
                                       xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                                    </xsl:if>
                                 </xsl:otherwise>
                             </xsl:choose>
                             <xsl:if test="not($simple)">
                                   xmlWriter.writeEndElement();
                             </xsl:if>
                        </xsl:otherwise>
                    </xsl:choose>
                    <xsl:if test="$min=0 or $choice">}</xsl:if>

                </xsl:for-each>
                   <!-- write the end element for the type-->
               xmlWriter.writeEndElement();
            <!-- end of when for type & anon -->
            </xsl:when>

            <!-- Not a type and not anon. So it better be only one inclusion-->
            <xsl:otherwise>
                <!-- if the element is associated with a type, then its gonna be only one -->
                //We can safely assume an element has only one type associated with it
                <xsl:variable name="varName">local<xsl:value-of select="property/@javaname"/></xsl:variable>
                <xsl:variable name="nillable" select="property/@nillable"></xsl:variable>
                <xsl:variable name="primitive" select="property/@primitive"></xsl:variable>
                <xsl:variable name="propertyType"><xsl:value-of select="property/@type"/></xsl:variable>

                <xsl:choose>
                    <!-- This better be only one!!-->
                    <xsl:when test="property/@ours">
                        <xsl:choose>
                            <xsl:when test="$nillable">
                                      if (<xsl:value-of select="$varName"/>==null){
                                        java.lang.String namespace = "<xsl:value-of select="property/@nsuri"/>";

                                        if (! namespace.equals("")) {
                                            java.lang.String prefix = xmlWriter.getPrefix(namespace);

                                            if (prefix == null) {
                                                prefix = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                                xmlWriter.writeStartElement(prefix,"<xsl:value-of select="property/@name"/>", namespace);
                                                xmlWriter.writeNamespace(prefix, namespace);
                                                xmlWriter.setPrefix(prefix, namespace);

                                            } else {
                                                xmlWriter.writeStartElement(namespace,"<xsl:value-of select="property/@name"/>");
                                            }

                                        } else {
                                            xmlWriter.writeStartElement("<xsl:value-of select="property/@name"/>");
                                        }

                                        // write the nil attribute
                                        writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                        xmlWriter.writeEndElement();
                                       }else{
                                         <xsl:value-of select="$varName"/>.getOMDataSource(
                                         MY_QNAME,
                                         factory).serialize(xmlWriter);
                                       }
                            </xsl:when>
                            <xsl:otherwise>
                                 if (<xsl:value-of select="$varName"/>==null){
                                   throw new RuntimeException("Property cannot be null!");
                                 }
                                 <xsl:value-of select="$varName"/>.getOMDataSource(
                                         MY_QNAME,
                                         factory).serialize(xmlWriter);
                            </xsl:otherwise>
                        </xsl:choose>
                    </xsl:when>
                    <!-- end of ours block-->
                    <xsl:otherwise>
                        <xsl:if test="not(property/@simple)">
                            java.lang.String namespace = "<xsl:value-of select="property/@nsuri"/>";
                            java.lang.String localName = "<xsl:value-of select="property/@name"/>";
                        </xsl:if>
                        <xsl:if test="property/@simple">
                            java.lang.String namespace = parentQName.getNamespaceURI();
                            java.lang.String localName = parentQName.getLocalPart();
                        </xsl:if>
                            if (! namespace.equals("")) {
                                java.lang.String prefix = xmlWriter.getPrefix(namespace);

                                if (prefix == null) {
                                    prefix = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();

                                    xmlWriter.writeStartElement(prefix, localName, namespace);
                                    xmlWriter.writeNamespace(prefix, namespace);
                                    xmlWriter.setPrefix(prefix, namespace);

                                } else {
                                    xmlWriter.writeStartElement(namespace, localName);
                                }

                            } else {
                                xmlWriter.writeStartElement(localName);
                            }
                            <xsl:if test="not($primitive)">
                                          if (<xsl:value-of select="$varName"/>==null){
                                            <xsl:choose>
                                                <xsl:when test="$nillable">
                                                     // write the nil attribute
                                                     writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                                </xsl:when>
                                                <xsl:otherwise>
                                                     throw new RuntimeException("testValue cannot be null !!");
                                                </xsl:otherwise>
                                            </xsl:choose>
                                         }else{
                                        <xsl:choose>
                                            <xsl:when test="$propertyType='javax.xml.namespace.QName'">
                                                           java.lang.String prefix ="";
                                                            java.lang.String namespaceURI =<xsl:value-of select="$varName"/>.getNamespaceURI();
                                                            if(namespaceURI !=null){
                                                               prefix = <xsl:value-of select="$varName"/>.getPrefix();
                                                               if (prefix == null) {
                                                                prefix = org.apache.axis2.databinding.utils.BeanUtil.getUniquePrefix();
                                                              }
                                                             xmlWriter.writeNamespace(prefix,namespaceURI );
                                                             xmlWriter.writeCharacters(prefix + ":"+ org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                                                            } else {
                                                               xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                                                            }
                                            </xsl:when>
                                            <xsl:when test="$propertyType='org.apache.axiom.om.OMElement'">
                                                <xsl:value-of select="$varName"/>.serialize(xmlWriter);
                                            </xsl:when>
                                            <xsl:when test="$propertyType='java.lang.String'">
                                                       xmlWriter.writeCharacters(<xsl:value-of select="$varName"/>);
                                            </xsl:when>
                                            <xsl:otherwise>
                                                       xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                                            </xsl:otherwise>
                                        </xsl:choose>
                                         }
                                    </xsl:if>
                            <xsl:if test="$primitive">
                               xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                            </xsl:if>
                       xmlWriter.writeEndElement();
                    </xsl:otherwise>
                </xsl:choose>
            </xsl:otherwise>
        </xsl:choose>

        }

         /**
          * Util method to write an attribute with the ns prefix
          */
          private void writeAttribute(java.lang.String prefix,java.lang.String namespace,java.lang.String attName,
                                      java.lang.String attValue,javax.xml.stream.XMLStreamWriter xmlWriter) throws javax.xml.stream.XMLStreamException{
              if (xmlWriter.getPrefix(namespace) == null) {
                       xmlWriter.writeNamespace(prefix, namespace);
                       xmlWriter.setPrefix(prefix, namespace);

              }

              xmlWriter.writeAttribute(namespace,attName,attValue);

         }

         /**
          * Util method to write an attribute without the ns prefix
          */
          private void writeAttribute(java.lang.String namespace,java.lang.String attName,
                                      java.lang.String attValue,javax.xml.stream.XMLStreamWriter xmlWriter) throws javax.xml.stream.XMLStreamException{
    	  	  if (namespace.equals(""))
        	  {
        		  xmlWriter.writeAttribute(attName,attValue);
        	  }
        	  else
        	  {
                  registerPrefix(xmlWriter, namespace);
                  xmlWriter.writeAttribute(namespace,attName,attValue);
              }
          }

         /**
         * Register a namespace prefix
         */
         private java.lang.String registerPrefix(javax.xml.stream.XMLStreamWriter xmlWriter, java.lang.String namespace) throws javax.xml.stream.XMLStreamException {
                java.lang.String prefix = xmlWriter.getPrefix(namespace);

                if (prefix == null) {
                    prefix = createPrefix();

                    while (xmlWriter.getNamespaceContext().getNamespaceURI(prefix) != null) {
                        prefix = createPrefix();
                    }

                    xmlWriter.writeNamespace(prefix, namespace);
                    xmlWriter.setPrefix(prefix, namespace);
                }

                return prefix;
            }

         /**
          * Create a prefix
          */
          private java.lang.String createPrefix() {
                return "ns" + (int)Math.random();
          }
        };

        return dataSource;
    }

  <!-- ######################################################################################### -->
        /**
        * databinding method to get an XML representation of this object
        *
        */
        public javax.xml.stream.XMLStreamReader getPullParser(javax.xml.namespace.QName qName){


        <xsl:choose>
            <xsl:when test="@type or @anon">
                 java.util.ArrayList elementList = new java.util.ArrayList();
                 java.util.ArrayList attribList = new java.util.ArrayList();

                <xsl:for-each select="property[not(@attribute)]">
                    <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                    <xsl:variable name="varName">local<xsl:value-of select="@javaname"/></xsl:variable>
                    <xsl:variable name="min"><xsl:value-of select="@minOccurs"/></xsl:variable>
                    <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                    <xsl:variable name="settingTracker">local<xsl:value-of select="@javaname"/>Tracker</xsl:variable>


                    <xsl:if test="$min=0 or $choice"> if (<xsl:value-of select="$settingTracker"/>){</xsl:if>
                    <xsl:choose>
                        <xsl:when test="(@ours or @default) and not(@array)">
                            elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                      "<xsl:value-of select="$propertyName"/>"));
                            <!-- Arraylist can handle null's -->
                            <xsl:choose>
                                <xsl:when test="@nillable">
                                    elementList.add(<xsl:value-of select="$varName"/>==null?null:
                                    <xsl:value-of select="$varName"/>);
                                </xsl:when>
                                <xsl:otherwise>
                                    if (<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }
                                    elementList.add(<xsl:value-of select="$varName"/>);
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:when>
                        <xsl:when test="(@ours or @default) and @array">
                             if (<xsl:value-of select="$varName"/>!=null) {
                                 for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){

                                    if (<xsl:value-of select="$varName"/>[i] != null){
                                         elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                          "<xsl:value-of select="$propertyName"/>"));
                                         elementList.add(<xsl:value-of select="$varName"/>[i]);
                                    } else {
                                        <xsl:choose>
                                            <xsl:when test="@nillable">
                                                elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                          "<xsl:value-of select="$propertyName"/>"));
                                                elementList.add(null);
                                            </xsl:when>
                                            <xsl:when test="$min=0">
                                                // nothing to do
                                            </xsl:when>
                                            <xsl:otherwise>
                                               throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null !!");
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    }

                                 }
                             } else {
                                 <xsl:choose>
                                    <xsl:when test="@nillable">
                                        elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                          "<xsl:value-of select="$propertyName"/>"));
                                        elementList.add(<xsl:value-of select="$varName"/>);
                                    </xsl:when>
                                    <xsl:otherwise>
                                        throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    </xsl:otherwise>
                                </xsl:choose>
                             }

                        </xsl:when>
                        <!-- handle non ADB arrays - Not any however -->
                        <xsl:when test="@array and not(@any)">
                            if (<xsl:value-of select="$varName"/>!=null){
                                  for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                                      <xsl:if test="not(@primitive)">
                                         if (<xsl:value-of select="$varName"/>[i] != null){
                                          elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                              "<xsl:value-of select="$propertyName"/>"));
                                          elementList.add(
                                          org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>[i]));
                                          } else {
                                             <xsl:choose>
                                                <xsl:when test="@nillable">
                                                    elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                              "<xsl:value-of select="$propertyName"/>"));
                                                    elementList.add(null);
                                                </xsl:when>
                                                <xsl:when test="$min=0">
                                                    // have to do nothing
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                                </xsl:otherwise>
                                            </xsl:choose>
                                          }
                                      </xsl:if>
                                      <xsl:if test="@primitive">
                                          elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                                                                       "<xsl:value-of select="$propertyName"/>"));
                                          elementList.add(
                                          org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>[i]));

                                      </xsl:if>

                                  }
                            } else {
                              <xsl:choose>
                                <xsl:when test="@nillable">
                                    elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                              "<xsl:value-of select="$propertyName"/>"));
                                    elementList.add(null);
                                </xsl:when>
                                <xsl:otherwise>
                                    throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                </xsl:otherwise>
                               </xsl:choose>
                            }

                        </xsl:when>

                         <!-- handle non ADB arrays  - Any case  - any may not be
                         nillable -->
                        <xsl:when test="@array and @any">
                            if (<xsl:value-of select="$varName"/> != null) {
                                for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                                    if (<xsl:value-of select="$varName"/>[i] != null){
                                       elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                          "<xsl:value-of select="$propertyName"/>"));
                                      elementList.add(
                                      org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>[i]));
                                    } else {
                                        <xsl:choose>
                                            <xsl:when test="$min=0">
                                                // have to do nothing
                                            </xsl:when>
                                            <xsl:otherwise>
                                                throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    }

                                }
                            } else {
                               throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                            }
                        </xsl:when>
                        <!-- handle any - non array case-->
                         <xsl:when test="@any">
                            if (<xsl:value-of select="$varName"/> != null){
                                elementList.add(org.apache.axis2.databinding.utils.Constants.OM_ELEMENT_KEY);
                                elementList.add(<xsl:value-of select="$varName"/>);
                            } else {
                               throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                            }
                        </xsl:when>
                        <!-- handle binary - Since it is a Datahandler, we can just add it to the list
                          and the ADB pullparser would handle it right-->
                         <xsl:when test="@binary">
                            elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                      "<xsl:value-of select="$propertyName"/>"));
                            elementList.add(<xsl:value-of select="$varName"/>);
                        </xsl:when>
                        <!-- the usual case!!!!-->
                        <xsl:otherwise>
                             elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                      "<xsl:value-of select="$propertyName"/>"));
                            <xsl:if test="@primitive">
                                elementList.add(
                                   org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                            </xsl:if>
                            <xsl:if test="not(@primitive)">
                                 <xsl:choose>
                                    <xsl:when test="@nillable">
                                         elementList.add(<xsl:value-of select="$varName"/>==null?null:
                                         org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                                    </xsl:when>
                                    <xsl:otherwise>
                                        if (<xsl:value-of select="$varName"/> != null){
                                            elementList.add(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                                        } else {
                                           throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                        }
                                    </xsl:otherwise>
                                </xsl:choose>
                           </xsl:if>

                        </xsl:otherwise>
                    </xsl:choose>
                    <xsl:if test="$min=0 or $choice">}</xsl:if>
                </xsl:for-each>

                <xsl:for-each select="property[@attribute]">
                    <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                    <xsl:variable name="varName">local<xsl:value-of select="@javaname"/></xsl:variable>
                     <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                    <xsl:choose>
                        <xsl:when test="@any and not(@array)">
                            attribList.add(org.apache.axis2.databinding.utils.Constants.OM_ATTRIBUTE_KEY);
                            attribList.add(<xsl:value-of select="$varName"/>);
                        </xsl:when>
                         <xsl:when test="@any and @array">
                             for (int i=0;i &lt;<xsl:value-of select="$varName"/>.length;i++){
                               attribList.add(org.apache.axis2.databinding.utils.Constants.OM_ATTRIBUTE_KEY);
                               attribList.add(<xsl:value-of select="$varName"/>[i]);
                             }
                         </xsl:when>
                        <xsl:otherwise>
                            attribList.add(
                            new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>"));
                            attribList.add(
                            org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                        </xsl:otherwise>
                    </xsl:choose>
                </xsl:for-each>

                return new org.apache.axis2.databinding.utils.reader.ADBXMLStreamReaderImpl(qName, elementList.toArray(), attribList.toArray());
            <!-- end of when for type & anon -->
            </xsl:when>
            <!-- Not a type and not anon. So it better be only one inclusion-->
            <xsl:otherwise>
                <!-- if the element is associated with a type, then its gonna be only one -->
                //We can safely assume an element has only one type associated with it
                <xsl:variable name="varName">local<xsl:value-of select="property/@javaname"/></xsl:variable>
                <xsl:variable name="nillable" select="property/@nillable"></xsl:variable>
                <xsl:variable name="primitive" select="property/@primitive"></xsl:variable>

                <xsl:choose>
                    <!-- This better be only one!!-->
                    <xsl:when test="property/@ours">

                        <xsl:choose>
                            <xsl:when test="$nillable">
                                if (<xsl:value-of select="$varName"/>==null){
                                   return new org.apache.axis2.databinding.utils.reader.NullXMLStreamReader(MY_QNAME);
                                }else{
                                   return <xsl:value-of select="$varName"/>.getPullParser(MY_QNAME);
                                }
                            </xsl:when>
                            <xsl:otherwise>return <xsl:value-of select="$varName"/>.getPullParser(MY_QNAME);</xsl:otherwise>
                        </xsl:choose>
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:choose>
                            <xsl:when test="$nillable and not($primitive)">
                                if (<xsl:value-of select="$varName"/>==null){
                                      return new org.apache.axis2.databinding.utils.reader.NullXMLStreamReader(MY_QNAME);
                                }else{
                                   return new org.apache.axis2.databinding.utils.reader.ADBXMLStreamReaderImpl(MY_QNAME,
                                       new java.lang.Object[]{
                                      org.apache.axis2.databinding.utils.reader.ADBXMLStreamReader.ELEMENT_TEXT,
                                       org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>)
                                       },
                                       null);
                                }
                            </xsl:when>
                            <xsl:otherwise> return new org.apache.axis2.databinding.utils.reader.ADBXMLStreamReaderImpl(MY_QNAME,
                            new java.lang.Object[]{
                            org.apache.axis2.databinding.utils.reader.ADBXMLStreamReader.ELEMENT_TEXT,
                            org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>)
                            },
                            null);</xsl:otherwise>
                        </xsl:choose>
                    </xsl:otherwise>
                </xsl:choose>
            </xsl:otherwise>
        </xsl:choose>

        }

  <!-- ######################################################################################### -->

     /**
      *  Factory class that keeps the parse method
      */
    public static class Factory{


        /**
        * static method to create the object
        * Precondition:  If this object is an element, the current or next start element starts this object and any intervening reader events are ignorable
        *                If this object is not an element, it is a complex type and the reader is at the event just after the outer start element
        * Postcondition: If this object is an element, the reader is positioned at its end element
        *                If this object is a complex type, the reader is positioned at the end element of its outer element
        */
        public static <xsl:value-of select="$name"/> parse(javax.xml.stream.XMLStreamReader reader) throws java.lang.Exception{
            <xsl:if test="not(property/enumFacet)"><xsl:value-of select="$name"/> object = new <xsl:value-of select="$name"/>();</xsl:if>
            <xsl:if test="property/enumFacet"><xsl:value-of select="$name"/> object = null;</xsl:if>
            int event;
            try {
                <!-- Advance to our start element, or if we are a complex type, to our first property start element or the outer end element if no properties -->
                while (!reader.isStartElement() &amp;&amp; !reader.isEndElement())
                    reader.next();

                <xsl:if test="@nillable">
                   if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                         // Skip the element and report the null value.  It cannot have subelements.
                         while (!reader.isEndElement())
                             reader.next();
                         <xsl:choose>
                             <xsl:when test="@type or @anon">
                                 return null;
                             </xsl:when>
                             <xsl:otherwise>
                                 return object;
                             </xsl:otherwise>
                         </xsl:choose>

                   }
                </xsl:if>
                  <xsl:if test="$isType or $anon">
                if (reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","type")!=null){
                  java.lang.String fullTypeName = reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance",
                        "type");
                  if (fullTypeName!=null){
                    java.lang.String nsPrefix = fullTypeName.substring(0,fullTypeName.indexOf(":"));
                    nsPrefix = nsPrefix==null?"":nsPrefix;

                    java.lang.String type = fullTypeName.substring(fullTypeName.indexOf(":")+1);
                    if (!"<xsl:value-of select="$originalName"/>".equals(type)){
                        //find namespace for the prefix
                        java.lang.String nsUri = reader.getNamespaceContext().getNamespaceURI(nsPrefix);
                        return (<xsl:value-of select="$name"/>)<xsl:value-of select="$mapperClass"/>.getTypeObject(
                             nsUri,type,reader);
                      }

                  }

                }
                </xsl:if>

                <!-- populate attributes here!!!. The attributes are part of an element, not part of a type -->
                // Note all attributes that were handled. Used to differ normal attributes
                // from anyAttributes.
                java.util.Vector handledAttributes = new java.util.Vector();
                <xsl:for-each select="property[@attribute]">
                    <xsl:variable name="propertyName" select="@name"/>
                    <xsl:variable name="propertyType" select="@type"/>
                    <xsl:variable name="shortTypeNameUncapped"  select="@shorttypename"/>
                    <xsl:variable name="shortTypeName"
                    select="concat(translate(substring($shortTypeNameUncapped, 1, 1 ),'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' ), substring($shortTypeNameUncapped, 2, string-length($shortTypeNameUncapped)))" />
                    <xsl:variable name="javaName" select="@javaname"/>
                    <xsl:variable name="namespace" select="@nsuri"/>
                    <xsl:variable name="attribName">tempAttrib<xsl:value-of select="$propertyName"/></xsl:variable>

                    <xsl:if test="$propertyName != 'extraAttributes'">
                    // handle attribute "<xsl:value-of select="$propertyName"/>"
                    java.lang.String <xsl:value-of select="$attribName"/> =
                      reader.getAttributeValue("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>");
                   if (<xsl:value-of select="$attribName"/>!=null){
                         java.lang.String content = <xsl:value-of select="$attribName"/>;
                        <xsl:choose>
                            <xsl:when test="$propertyType='javax.xml.namespace.QName'">
                                int index = <xsl:value-of select="$attribName"/>.indexOf(":");
                                java.lang.String prefix ="";
                                java.lang.String namespaceuri ="";
                                if(index >0){
                                     prefix = <xsl:value-of select="$attribName"/>.substring(0,index);
                                     namespaceuri = reader.getNamespaceURI(prefix);
                                 }
                                 object.set<xsl:value-of select="$javaName"/>(
                                      org.apache.axis2.databinding.utils.ConverterUtil.convertToQName(<xsl:value-of select="$attribName"/>,namespaceuri));
                            </xsl:when>
                            <xsl:otherwise>
                         object.set<xsl:value-of select="$javaName"/>(
                           org.apache.axis2.databinding.utils.ConverterUtil.convertTo<xsl:value-of select="$shortTypeName"/>(
                                <xsl:value-of select="$attribName"/>));
                            </xsl:otherwise>
                        </xsl:choose>
                    }
                    handledAttributes.add("<xsl:value-of select="$propertyName"/>");
                    </xsl:if>

                    <!-- Handle anyAttributes here -->
                    <xsl:if test="$propertyName = 'extraAttributes'">
                        // now run through all any or extra attributes
                        // which were not reflected until now
                        for (int i=0; i &lt; reader.getAttributeCount(); i++) {
                            if (!handledAttributes.contains(reader.getAttributeLocalName(i))) {
                                // this is an anyAttribute and we create
                                // an OMAttribute for this
                                org.apache.axiom.om.impl.llom.OMAttributeImpl attr =
                                    new org.apache.axiom.om.impl.llom.OMAttributeImpl(
                                            reader.getAttributeLocalName(i),
                                            new org.apache.axiom.om.impl.dom.NamespaceImpl(
                                                reader.getAttributeNamespace(i), reader.getAttributePrefix(i)),
                                            reader.getAttributeValue(i),
                                            org.apache.axiom.om.OMAbstractFactory.getOMFactory());

                                // and add it to the extra attributes
                                object.addExtraAttributes(attr);
                            }
                        }
                    </xsl:if>

                </xsl:for-each>

                <xsl:if test="($isType or $anon) and not($simple)">
                    <!-- Skip the outer start element in order to process the subelements. -->
                    reader.next();
                </xsl:if>
                      <!-- If we are not a type and not an element with anonymous type, then we are an element with one property for our named type. -->
                      <!-- Our single named-type property applies to our entire outer element, so don't skip it. -->
                <!-- First loop creates arrayLists for handling arrays -->
                <xsl:for-each select="property[not(@attribute)]">
                    <xsl:if test="@array">
                        java.util.ArrayList list<xsl:value-of select="position()"/> = new java.util.ArrayList();
                    </xsl:if>
                </xsl:for-each>

                <xsl:if test="property[not(@attribute)]">
                <xsl:if test="$unordered">   <!-- Properties can be in any order -->
                while(!reader.isEndElement()) {
                    if (reader.isStartElement() <xsl:if test="$simple"> || reader.hasText()</xsl:if>){
                </xsl:if>
                </xsl:if>

                        <!-- Now reloop and populate the code -->
                        <xsl:for-each select="property[not(@attribute)]">
                            <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                            <xsl:variable name="propertyType"><xsl:value-of select="@type"/></xsl:variable>
                            <xsl:variable name="shortTypeNameUncapped"  select="@shorttypename"/>
                            <xsl:variable name="shortTypeName"
                                select="concat(translate(substring($shortTypeNameUncapped, 1, 1 ),'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' ), substring($shortTypeNameUncapped, 2, string-length($shortTypeNameUncapped)))" />
                            <xsl:variable name="javaName"><xsl:value-of select="@javaname"></xsl:value-of></xsl:variable>
                            <xsl:variable name="listName">list<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="loopBoolName">loopDone<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="startQname">startQname<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="stateMachineName">stateMachine<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="builderName">builder<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="basePropertyType"><xsl:value-of select="@arrayBaseType"/></xsl:variable>
                            <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                            <xsl:variable name="min"><xsl:value-of select="@minOccurs"/></xsl:variable>

                            <xsl:variable name="propQName">new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>")</xsl:variable>

                           <xsl:choose>
                                <xsl:when test="$unordered">  <!-- One property per iteration if unordered -->
                                    <xsl:if test="position()>1">
                                        else
                                    </xsl:if>
                                </xsl:when>
                                <xsl:otherwise>
                                    <!-- If sequence, advance to start of next property or to end of outer element -->
                                    while (!reader.isStartElement() &amp;&amp; !reader.isEndElement()) reader.next();
                                </xsl:otherwise>
                            </xsl:choose>

                            <xsl:if test="not(enumFacet)">
                            <xsl:choose>
                                <xsl:when test="$shortTypeName='OMElement'">
                                   if (reader.isStartElement()){
                                </xsl:when>
                                <xsl:otherwise>
                                    if (reader.isStartElement() <xsl:if test="$simple"> || reader.hasText()</xsl:if> <xsl:if test="not($simple)">&amp;&amp; <xsl:value-of select="$propQName"/>.equals(reader.getName())</xsl:if>){
                                </xsl:otherwise>
                            </xsl:choose>

                            </xsl:if>
                            <xsl:choose>
                                <xsl:when test="@array">
                                    <!-- We must be a named type or element with anonymous type. -->
                                    <!-- Elements with a named type have a single simple (non-array) property for their type -->
                                    // Process the array and step past its final element's end.
                                    <xsl:variable name="basePropertyType"><xsl:value-of select="@arrayBaseType"/></xsl:variable>
                                    <xsl:choose>
                                        <xsl:when test="@ours">
                                             <xsl:if test="@nillable">
                                              if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                  <xsl:value-of select="$listName"/>.add(null);
                                                  reader.next();
                                              } else {
                                            </xsl:if>
                                                <xsl:value-of select="$listName"/>.add(<xsl:value-of select="$basePropertyType"/>.Factory.parse(reader));
                                            <xsl:if test="@nillable">}</xsl:if>
                                            //loop until we find a start element that is not part of this array
                                            boolean <xsl:value-of select="$loopBoolName"/> = false;
                                            while(!<xsl:value-of select="$loopBoolName"/>){
                                                // We should be at the end element, but make sure
                                                while (!reader.isEndElement())
                                                    reader.next();
                                                // Step out of this element
                                                reader.next();
                                                // Step to next element event.
                                                while (!reader.isStartElement() &amp;&amp; !reader.isEndElement())
                                                    reader.next();
                                                if (reader.isEndElement()){
                                                    //two continuous end elements means we are exiting the xml structure
                                                    <xsl:value-of select="$loopBoolName"/> = true;
                                                } else {
                                                    if (<xsl:value-of select="$propQName"/>.equals(reader.getName())){
                                                        <xsl:if test="@nillable">
                                                          if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                              <xsl:value-of select="$listName"/>.add(null);
                                                              reader.next();
                                                          } else {
                                                        </xsl:if>
                                                        <xsl:value-of select="$listName"/>.add(<xsl:value-of select="$basePropertyType"/>.Factory.parse(reader));
                                                        <xsl:if test="@nillable">}</xsl:if>
                                                    }else{
                                                        <xsl:value-of select="$loopBoolName"/> = true;
                                                    }
                                                }
                                            }
                                            // call the converter utility  to convert and set the array
                                            object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                    <xsl:value-of select="$basePropertyType"/>.class,
                                                    <xsl:value-of select="$listName"/>));
                                        </xsl:when>
                                        <!-- End of Array handling of ADB classes -->

                                        <!--Let's handle xs:any here-->
                                        <xsl:when test="@any">
                                           boolean <xsl:value-of select="$loopBoolName"/>=false;

                                             while (!<xsl:value-of select="$loopBoolName"/>){
                                                 event = reader.getEventType();
                                                 if (javax.xml.stream.XMLStreamConstants.START_ELEMENT == event){

                                                      // We need to wrap the reader so that it produces a fake START_DOCUEMENT event
                                                      org.apache.axis2.databinding.utils.NamedStaxOMBuilder <xsl:value-of select="$builderName"/>
                                                         = new org.apache.axis2.databinding.utils.NamedStaxOMBuilder(
                                                              new org.apache.axis2.util.StreamWrapper(reader), reader.getName());

                                                       <xsl:value-of select="$listName"/>.add(<xsl:value-of select="$builderName"/>.getOMElement());
                                                        reader.next();
                                                        if (reader.isEndElement()) {
                                                            // we have two countinuos end elements
                                                           <xsl:value-of select="$loopBoolName"/> = true;
                                                        }

                                                 }else if (javax.xml.stream.XMLStreamConstants.END_DOCUMENT == event){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else{
                                                     reader.next();
                                                 }

                                             }

                                             object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                 org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                     <xsl:value-of select="$basePropertyType"/>.class,<xsl:value-of select="$listName"/>));
                                        </xsl:when>

                                        <!-- End of Array handling of ADB classes -->
                                        <xsl:when test="@default">

                                             boolean <xsl:value-of select="$loopBoolName"/>=false;
                                             javax.xml.namespace.QName <xsl:value-of select="$startQname"/> = new javax.xml.namespace.QName(
                                                    "<xsl:value-of select="$namespace"/>",
                                                    "<xsl:value-of select="$propertyName"/>");

                                             while (!<xsl:value-of select="$loopBoolName"/>){
                                                 event = reader.getEventType();
                                                 if (javax.xml.stream.XMLStreamConstants.START_ELEMENT == event
                                                         &amp;&amp; <xsl:value-of select="$startQname"/>.equals(reader.getName())){

                                                      <!-- if-block that handles nillable -->
                                                      <xsl:if test="@nillable">
                                                          if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                              <xsl:value-of select="$listName"/>.add(null);
                                                              reader.next();
                                                          }else{
                                                      </xsl:if>
                                                            // we parse it as an omElement
                                                            // We need to wrap the reader so that it produces a fake START_DOCUEMENT event
                                                            // this is needed by the builder classes
                                                             org.apache.axis2.databinding.utils.NamedStaxOMBuilder <xsl:value-of select="$builderName"/> =
                                                                 new org.apache.axis2.databinding.utils.NamedStaxOMBuilder(
                                                                     new org.apache.axis2.util.StreamWrapper(reader),<xsl:value-of select="$startQname"/>);
                                                             <xsl:value-of select="$listName"/>.add(<xsl:value-of select="$builderName"/>.getOMElement().getFirstElement());
                                                       <xsl:if test="@nillable">}</xsl:if>
                                                 } else if (javax.xml.stream.XMLStreamConstants.START_ELEMENT == event &amp;&amp;
                                                            !<xsl:value-of select="$startQname"/>.equals(reader.getName())){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else if (javax.xml.stream.XMLStreamConstants.END_ELEMENT == event &amp;&amp;
                                                           !<xsl:value-of select="$startQname"/>.equals(reader.getName())){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else if (javax.xml.stream.XMLStreamConstants.END_DOCUMENT == event){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else{
                                                     reader.next();
                                                 }

                                             }

                                             object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                 org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                     <xsl:value-of select="$basePropertyType"/>.class,<xsl:value-of select="$listName"/>));

                                        </xsl:when>

                                        <!-- handling binary case -->
                                        <xsl:when test="@binary">
                                               <xsl:if test="@nillable">
                                                  if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                      <xsl:value-of select="$listName"/>.add(null);
                                                      reader.next();
                                                  } else {
                                                </xsl:if>

                                                    if (isReaderMTOMAware(reader)
                                                            &amp;&amp;
                                                            java.lang.Boolean.TRUE.equals(reader.getProperty(org.apache.axiom.om.OMConstants.IS_BINARY)))
                                                    {
                                                        //MTOM aware reader - get the datahandler directly and put it in the object
                                                        <xsl:value-of select="$listName"/>.add(
                                                                (javax.activation.DataHandler) reader.getProperty(org.apache.axiom.om.OMConstants.DATA_HANDLER));
                                                    } else {
                                                        // Step in
                                                        if (reader.getEventType() == javax.xml.stream.XMLStreamConstants.START_ELEMENT &amp;&amp; <xsl:value-of select="$propQName"/>.equals(reader.getName())) {
                                                            reader.next();
                                                        }
                                                        if (reader.getEventType() == javax.xml.stream.XMLStreamConstants.START_ELEMENT &amp;&amp; reader.getName().equals(new javax.xml.namespace.QName(org.apache.axiom.om.impl.MTOMConstants.XOP_NAMESPACE_URI, org.apache.axiom.om.impl.MTOMConstants.XOP_INCLUDE)))
                                                        {
                                                            java.lang.String id = org.apache.axiom.om.util.ElementHelper.getContentID(reader, "UTF-8");
                                                            <xsl:value-of select="$listName"/>.add(((org.apache.axiom.soap.impl.builder.MTOMStAXSOAPModelBuilder) ((org.apache.axiom.om.impl.llom.OMStAXWrapper) reader).getBuilder()).getDataHandler(id));
                                                            reader.next();
                                                            reader.next();
                                                        } else if(reader.hasText()) {
                                                            //Do the usual conversion
                                                            java.lang.String content = reader.getText();
                                                            <xsl:value-of select="$listName"/>.add(
                                                                    org.apache.axis2.databinding.utils.ConverterUtil.convertToBase64Binary(content));
                                                                    reader.next();
                                                        }

                                                    }


                                                <xsl:if test="@nillable">}</xsl:if>
                                                //loop until we find a start element that is not part of this array
                                                boolean <xsl:value-of select="$loopBoolName"/> = false;
                                                while(!<xsl:value-of select="$loopBoolName"/>){
                                                    // Ensure we are at the EndElement
                                                    while (!reader.isEndElement()){
                                                        reader.next();
                                                    }
                                                    // Step out of this element
                                                    reader.next();
                                                    // Step to next element event.
                                                    while (!reader.isStartElement() &amp;&amp; !reader.isEndElement())
                                                        reader.next();
                                                    if (reader.isEndElement()){
                                                        //two continuous end elements means we are exiting the xml structure
                                                        <xsl:value-of select="$loopBoolName"/> = true;
                                                    } else {
                                                        if (<xsl:value-of select="$propQName"/>.equals(reader.getName())){
                                                             <xsl:if test="@nillable">
                                                              if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                                  <xsl:value-of select="$listName"/>.add(null);
                                                                  reader.next();
                                                              } else {
                                                            </xsl:if>

                                                                <xsl:if test="not($simple)">reader.next();</xsl:if>
                                                                if (isReaderMTOMAware(reader)
                                                                        &amp;&amp;
                                                                        java.lang.Boolean.TRUE.equals(reader.getProperty(org.apache.axiom.om.OMConstants.IS_BINARY)))
                                                                {
                                                                    //MTOM aware reader - get the datahandler directly and put it in the object
                                                                    <xsl:value-of select="$listName"/>.add(
                                                                            (javax.activation.DataHandler) reader.getProperty(org.apache.axiom.om.OMConstants.DATA_HANDLER));
                                                                } else {
                                                                    if (reader.getEventType() == javax.xml.stream.XMLStreamConstants.START_ELEMENT &amp;&amp; reader.getName().equals(new javax.xml.namespace.QName(org.apache.axiom.om.impl.MTOMConstants.XOP_NAMESPACE_URI, org.apache.axiom.om.impl.MTOMConstants.XOP_INCLUDE)))
                                                                    {
                                                                        java.lang.String id = org.apache.axiom.om.util.ElementHelper.getContentID(reader, "UTF-8");
                                                                        <xsl:value-of select="$listName"/>.add(((org.apache.axiom.soap.impl.builder.MTOMStAXSOAPModelBuilder) ((org.apache.axiom.om.impl.llom.OMStAXWrapper) reader).getBuilder()).getDataHandler(id));
                                                                        reader.next();
                                                                        reader.next();
                                                                    } else if(reader.hasText()) {
                                                                        //Do the usual conversion
                                                                        java.lang.String content = reader.getText();
                                                                        <xsl:value-of select="$listName"/>.add(
                                                                                org.apache.axis2.databinding.utils.ConverterUtil.convertToBase64Binary(content));
                                                                                reader.next();
                                                                    }

                                                                }

                                                            <xsl:if test="@nillable">}</xsl:if>
                                                        }else{
                                                            <xsl:value-of select="$loopBoolName"/> = true;
                                                        }
                                                    }
                                                }
                                                // call the converter utility  to convert and set the array
                                                object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                    org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                        <xsl:value-of select="$basePropertyType"/>.class,
                                                        <xsl:value-of select="$listName"/>));
                                        </xsl:when>

                                        <xsl:otherwise>
                                            <xsl:choose>
                                             <xsl:when test="@default">
                                             boolean <xsl:value-of select="$loopBoolName"/>=false;
                                             javax.xml.namespace.QName <xsl:value-of select="$startQname"/> = new javax.xml.namespace.QName(
                                                    "<xsl:value-of select="$namespace"/>",
                                                    "<xsl:value-of select="$propertyName"/>");

                                             while (!<xsl:value-of select="$loopBoolName"/>){
                                                 event = reader.getEventType();
                                                 if (javax.xml.stream.XMLStreamConstants.START_ELEMENT == event
                                                         &amp;&amp; <xsl:value-of select="$startQname"/>.equals(reader.getName())){

                                                      <!-- if-block that handles nillable -->
                                                      <xsl:if test="@nillable">
                                                          if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                              <xsl:value-of select="$listName"/>.add(null);
                                                          }else{
                                                      </xsl:if>

                                                      // We need to wrap the reader so that it produces a fake START_DOCUEMENT event
                                                      org.apache.axis2.databinding.utils.NamedStaxOMBuilder <xsl:value-of select="$builderName"/>
                                                         = new org.apache.axis2.databinding.utils.NamedStaxOMBuilder(
                                                              new org.apache.axis2.util.StreamWrapper(reader), <xsl:value-of select="$startQname"/>);

                                                       <xsl:value-of select="$listName"/>.add(<xsl:value-of select="$builderName"/>.getOMElement().getFirstElement());
                                                       <xsl:if test="@nillable">}</xsl:if>
                                                 } else if (javax.xml.stream.XMLStreamConstants.START_ELEMENT == event &amp;&amp;
                                                            !<xsl:value-of select="$startQname"/>.equals(reader.getName())){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else if (javax.xml.stream.XMLStreamConstants.END_ELEMENT == event &amp;&amp;
                                                           !<xsl:value-of select="$startQname"/>.equals(reader.getName())){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else if (javax.xml.stream.XMLStreamConstants.END_DOCUMENT == event){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else{
                                                     reader.next();
                                                 }

                                             }

                                             object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                 org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                     <xsl:value-of select="$basePropertyType"/>.class,<xsl:value-of select="$listName"/>));

                                        </xsl:when>
                                        <!-- End of Array handling of default class - that is the OMElement -->
                                        <xsl:otherwise>
                                             <xsl:if test="@nillable">
                                              if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                  <xsl:value-of select="$listName"/>.add(null);
                                                  reader.next();
                                              } else {
                                            </xsl:if>
                                            <xsl:value-of select="$listName"/>.add(reader.getElementText());
                                            <xsl:if test="@nillable">}</xsl:if>
                                            //loop until we find a start element that is not part of this array
                                            boolean <xsl:value-of select="$loopBoolName"/> = false;
                                            while(!<xsl:value-of select="$loopBoolName"/>){
                                                // Ensure we are at the EndElement
                                                while (!reader.isEndElement()){
                                                    reader.next();
                                                }
                                                // Step out of this element
                                                reader.next();
                                                // Step to next element event.
                                                while (!reader.isStartElement() &amp;&amp; !reader.isEndElement())
                                                    reader.next();
                                                if (reader.isEndElement()){
                                                    //two continuous end elements means we are exiting the xml structure
                                                    <xsl:value-of select="$loopBoolName"/> = true;
                                                } else {
                                                    if (<xsl:value-of select="$propQName"/>.equals(reader.getName())){
                                                         <xsl:if test="@nillable">
                                                          if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                              <xsl:value-of select="$listName"/>.add(null);
                                                              reader.next();
                                                          } else {
                                                        </xsl:if>
                                                        <xsl:value-of select="$listName"/>.add(reader.getElementText());
                                                        <xsl:if test="@nillable">}</xsl:if>
                                                    }else{
                                                        <xsl:value-of select="$loopBoolName"/> = true;
                                                    }
                                                }
                                            }
                                            // call the converter utility  to convert and set the array
                                            object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                    <xsl:value-of select="$basePropertyType"/>.class,
                                                    <xsl:value-of select="$listName"/>));
                                        </xsl:otherwise>
                                        </xsl:choose>
                                        </xsl:otherwise>
                                    </xsl:choose>
                                </xsl:when>
                                <xsl:when test="@ours">
                                    <xsl:if test="@nillable">
                                      if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                          object.set<xsl:value-of select="$javaName"/>(null);
                                          reader.next();
                                          <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                            reader.next();
                                          </xsl:if>
                                      }else{
                                    </xsl:if>
                                        object.set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/>.Factory.parse(reader));
                                    <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                        reader.next();
                                    </xsl:if>
                                    <xsl:if test="@nillable">}</xsl:if>
                                </xsl:when>
                                <!-- start of any handling. Any can also be @default so we need to handle the any case before default! -->
                                <xsl:when test="@any">
                                    <!--No concerns of being nillable here. if it's ours and if the nillable attribute was present
                                        we would have outputted a null already-->
                                     <!--This can be any element and we may not know the name. so we pick the name of the element from the parser-->
                                     //use the QName from the parser as the name for the builder
                                     javax.xml.namespace.QName <xsl:value-of select="$startQname"/> = reader.getName();

                                     // We need to wrap the reader so that it produces a fake START_DOCUMENT event
                                     // this is needed by the builder classes
                                     org.apache.axis2.databinding.utils.NamedStaxOMBuilder <xsl:value-of select="$builderName"/> =
                                         new org.apache.axis2.databinding.utils.NamedStaxOMBuilder(
                                             new org.apache.axis2.util.StreamWrapper(reader),<xsl:value-of select="$startQname"/>);
                                     object.set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$builderName"/>.getOMElement());
                                     <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                         reader.next();
                                     </xsl:if>
                                </xsl:when>
                                <!-- end of adb type handling code -->
                                <!-- start of OMelement handling -->
                                 <xsl:when test="@default">
                                     boolean <xsl:value-of select="$loopBoolName"/> = false;
                                     javax.xml.namespace.QName <xsl:value-of select="$startQname"/> = new javax.xml.namespace.QName(
                                                                         "<xsl:value-of select="$namespace"/>",
                                                                         "<xsl:value-of select="$propertyName"/>");

                                     while(!<xsl:value-of select="$loopBoolName"/>){
                                         if (reader.isStartElement() &amp;&amp; <xsl:value-of select="$startQname"/>.equals(reader.getName())){
                                             <xsl:value-of select="$loopBoolName"/> = true;
                                         }else{
                                             reader.next();
                                         }
                                     }

                                     <!-- todo  put the code here for nillable -->
                                     // We need to wrap the reader so that it produces a fake START_DOCUEMENT event
                                     // this is needed by the builder classes
                                     org.apache.axis2.databinding.utils.NamedStaxOMBuilder <xsl:value-of select="$builderName"/> =
                                         new org.apache.axis2.databinding.utils.NamedStaxOMBuilder(
                                             new org.apache.axis2.util.StreamWrapper(reader),<xsl:value-of select="$startQname"/>);
                                     object.set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$builderName"/>.getOMElement().getFirstElement());
                                     <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                         reader.next();
                                     </xsl:if>
                                </xsl:when>
                                <!-- end of OMelement handling -->
                                <!-- start of the simple types handling for binary content-->
                                <xsl:when test="@binary">
                                    <xsl:if test="not($simple)">reader.next();</xsl:if>
                                    if (isReaderMTOMAware(reader)
                                            &amp;&amp;
                                            java.lang.Boolean.TRUE.equals(reader.getProperty(org.apache.axiom.om.OMConstants.IS_BINARY)))
                                    {
                                        //MTOM aware reader - get the datahandler directly and put it in the object
                                        object.set<xsl:value-of select="$javaName"/>(
                                                (javax.activation.DataHandler) reader.getProperty(org.apache.axiom.om.OMConstants.DATA_HANDLER));
                                    } else {
                                        if (reader.getEventType() == javax.xml.stream.XMLStreamConstants.START_ELEMENT &amp;&amp; reader.getName().equals(new javax.xml.namespace.QName(org.apache.axiom.om.impl.MTOMConstants.XOP_NAMESPACE_URI, org.apache.axiom.om.impl.MTOMConstants.XOP_INCLUDE)))
                                        {
                                            java.lang.String id = org.apache.axiom.om.util.ElementHelper.getContentID(reader, "UTF-8");
                                            object.set<xsl:value-of select="$javaName"/>(((org.apache.axiom.soap.impl.builder.MTOMStAXSOAPModelBuilder) ((org.apache.axiom.om.impl.llom.OMStAXWrapper) reader).getBuilder()).getDataHandler(id));
                                            reader.next();
                                            <xsl:if test="($isType or $anon) and not($simple)">
                                                reader.next();
                                            </xsl:if>
                                        } else if(reader.hasText()) {
                                            //Do the usual conversion
                                            java.lang.String content = reader.getText();
                                            object.set<xsl:value-of select="$javaName"/>(
                                                    org.apache.axis2.databinding.utils.ConverterUtil.convertToBase64Binary(content));
                                            <xsl:if test="($isType or $anon) and not($simple)">
                                                reader.next();
                                            </xsl:if>
                                        }
                                    }

                                    <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                        reader.next();
                                    </xsl:if>
                                </xsl:when>
                                <!-- start of the simple types handling -->
                                <xsl:otherwise>
                                    <xsl:if test="@nillable">
                                       if (!"true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                    </xsl:if>
                                    java.lang.String content = reader.getElementText();
                                    <xsl:if test="not(enumFacet)">
                                        <xsl:choose>
                                            <xsl:when test="$propertyType='javax.xml.namespace.QName'">
                                            int index = content.indexOf(":");
                                            java.lang.String prefix ="";
                                            java.lang.String namespaceuri ="";
                                            if(index >0){
                                                 prefix = content.substring(0,index);
                                                 namespaceuri = reader.getNamespaceURI(prefix);
                                             }
                                             object.set<xsl:value-of select="$javaName"/>(
                                                  org.apache.axis2.databinding.utils.ConverterUtil.convertToQName(content,namespaceuri));
                                            </xsl:when>
                                            <xsl:when test="$propertyType='org.apache.axiom.om.OMElement'">
                                                org.apache.axiom.om.OMFactory fac = org.apache.axiom.om.OMAbstractFactory.getOMFactory();
                                                org.apache.axiom.om.OMNamespace omNs = fac.createOMNamespace("<xsl:value-of select="$namespace"/>", "");
                                                org.apache.axiom.om.OMElement _value<xsl:value-of select="$javaName"/> = fac.createOMElement("<xsl:value-of select="$propertyName"/>", omNs);
                                                _value<xsl:value-of select="$javaName"/>.addChild(fac.createOMText(_value<xsl:value-of select="$javaName"/>, content));
                                                object.set<xsl:value-of select="$javaName"/>(_value<xsl:value-of select="$javaName"/>);
                                            </xsl:when>
                                            <xsl:otherwise>
                                              object.set<xsl:value-of select="$javaName"/>(
                                        org.apache.axis2.databinding.utils.ConverterUtil.convertTo<xsl:value-of select="$shortTypeName"/>(content));
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    </xsl:if>
                                    <xsl:if test="(enumFacet)">
                                    object = <xsl:value-of select="$name"/>.fromString(content);
                                    </xsl:if>
                                    <xsl:if test="@nillable">
                                       } else {
                                           reader.getElementText(); // throw away text nodes if any.
                                       }
                                    </xsl:if>
                                    <xsl:if test="($isType or $anon) and not($simple)">  <!-- This is a subelement property to be consumed -->
                                        reader.next();
                                    </xsl:if>
                                </xsl:otherwise>
                            </xsl:choose>
                            <xsl:if test="not(enumFacet)">
                              }  // End of if for expected property start element
                            </xsl:if>
                            <xsl:if test="$ordered and $min!=0">
                                else{
                                    // A start element we are not expecting indicates an invalid parameter was passed
                                    throw new java.lang.RuntimeException("Unexpected subelement " + reader.getLocalName());
                                }
                            </xsl:if>
                        </xsl:for-each>

                        <xsl:if test="$ordered">  <!-- pick up trailing cruft after final property before outer endElement and verify no trailing properties -->
                            while (!reader.isStartElement() &amp;&amp; !reader.isEndElement())
                                reader.next();
                            if (reader.isStartElement())
                                // A start element we are not expecting indicates a trailing invalid property
                                throw new java.lang.RuntimeException("Unexpected subelement " + reader.getLocalName());
                        </xsl:if>

                        <xsl:if test="property[not(@attribute)]">  <!-- this if is needed to skip all this when there are no propoerties-->
                        <xsl:if test="$unordered">
                          <xsl:if test="not(property/enumFacet)">
                             else{
                                        // A start element we are not expecting indicates an invalid parameter was passed
                                        throw new java.lang.RuntimeException("Unexpected subelement " + reader.getLocalName());
                             }
                          </xsl:if>
                             } else reader.next();  <!-- At neither a start nor an end element, skip it -->
                            }  // end of while loop
                        </xsl:if>
                        </xsl:if>


            } catch (javax.xml.stream.XMLStreamException e) {
                throw new java.lang.Exception(e);
            }

            return object;
        }

        }//end of factory class

        <!-- end of template for choice/all -->

        }
           <!-- end of main template -->
          </xsl:template>


<!-- $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$-->
<!-- $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$-->
<!-- $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$-->
<!-- $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$-->
<!-- $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$-->
<!-- $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$-->


    <!-- this is the common template -->
    <xsl:template match="bean[@helperMode]">

        <xsl:variable name="name"><xsl:value-of select="@name"/></xsl:variable>
        <xsl:variable name="choice" select="@choice"/>
        <xsl:variable name="ordered" select="@ordered"/>
        <xsl:variable name="unordered" select="not($ordered)"/>  <!-- for convenience -->
        <xsl:variable name="isType" select="@type"/>
        <xsl:variable name="anon" select="@anon"/>

        <xsl:variable name="nsuri" select="@nsuri"/>
        <xsl:variable name="originalName" select="@originalName"/>
        <xsl:variable name="nsprefix" select="@nsprefix"/>
        <xsl:variable name="extension" select="@extension"/>
         <xsl:variable name="mapperClass" select="@mapperClass"/>
         <xsl:variable name="package" select="@package"/>
        <xsl:variable name="helpername"><xsl:value-of select="$name"/>Helper</xsl:variable>
    <!-- write the class header. this should be done only when unwrapped -->

        <xsl:if test="not(not(@unwrapped) or (@skip-write))">
            /**
            * <xsl:value-of select="$name"/>.java
            *
            * This file was auto-generated from WSDL
            * by the Apache Axis2 version: #axisVersion# #today#
            */

            package <xsl:value-of select="$package"/>;
            /**
            *  <xsl:value-of select="$name"/> bean class
            */
        </xsl:if>


    <xsl:choose>
    <xsl:when test="not(@helper)">

    public <xsl:if test="not(@unwrapped) or (@skip-write)">static</xsl:if> class <xsl:value-of select="$name"/> <xsl:if test="$extension"> extends <xsl:value-of select="$extension"/></xsl:if>
        {
        <xsl:choose>
            <xsl:when test="@type">/* This type was generated from the piece of schema that had
                name = <xsl:value-of select="@originalName"/>
                Namespace URI = <xsl:value-of select="@nsuri"/>
                Namespace Prefix = <xsl:value-of select="@nsprefix"/>
                */
            </xsl:when>
            <xsl:otherwise>
                public static final javax.xml.namespace.QName MY_QNAME = new javax.xml.namespace.QName(
                "<xsl:value-of select="@nsuri"/>",
                "<xsl:value-of select="@originalName"/>",
                "<xsl:value-of select="@nsprefix"/>");

            </xsl:otherwise>
        </xsl:choose>

        <xsl:if test="$choice">
            /** Whenever a new property is set ensure all others are unset
             *  There can be only one choice and the last one wins
             */
            private void clearAllSettingTrackers() {
            <xsl:for-each select="property">
                local<xsl:value-of select="@javaname"/>Tracker = false;
           </xsl:for-each>
            }
        </xsl:if>


        <xsl:for-each select="property">
            <!-- Write only the NOT inherited properties-->
            <xsl:if test="not(@inherited)">

            <xsl:variable name="propertyType"><xsl:value-of select="@type"></xsl:value-of></xsl:variable>
            <xsl:variable name="propertyName"><xsl:value-of select="@name"></xsl:value-of></xsl:variable>
            <xsl:variable name="javaName"><xsl:value-of select="@javaname"></xsl:value-of></xsl:variable>

            <xsl:variable name="min"><xsl:value-of select="@minOccurs"/></xsl:variable>
            <xsl:variable name="varName">local<xsl:value-of select="$javaName"/></xsl:variable>
            <xsl:variable name="settingTracker">local<xsl:value-of select="$javaName"/>Tracker</xsl:variable>


            /**
            * field for <xsl:value-of select="$javaName"/>
            <xsl:if test="@attribute">* This was an Attribute!</xsl:if>
            <xsl:if test="@array">* This was an Array!</xsl:if>
            */

            protected <xsl:value-of select="$propertyType"/><xsl:text> </xsl:text><xsl:value-of select="$varName" /> ;
           <!-- Generate a tracker only if the min occurs is zero, which means if the user does
                not bother to set that value, we do not send it -->
           <xsl:if test="$min=0 or $choice">
           /*  This tracker boolean wil be used to detect whether the user called the set method
               for this attribute. It will be used to determine whether to include this field
               in the serialized XML
           */
           protected boolean <xsl:value-of select="$settingTracker"/> = false ;
           </xsl:if>

           /**
           * Auto generated getter method
           * @return <xsl:value-of select="$propertyType"/>
           */
           public  <xsl:value-of select="$propertyType"/><xsl:text> </xsl:text>get<xsl:value-of select="$javaName"/>(){
               return <xsl:value-of select="$varName"/>;
           }

           <!-- When generating the setters, we have to cater differently for the array!-->
            <xsl:choose>
               <xsl:when test="@array">
                   <xsl:variable name="basePropertyType"><xsl:value-of select="@arrayBaseType"/></xsl:variable>


                   <!-- generate the validator Method, this is specifiacally for validating the arrays-->
                  /**
                   * validate the array for <xsl:value-of select="$javaName"/>
                   */
                  protected void validate<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/> param){
                     <xsl:if test="not(@unbound)">
                          if ((param != null) &amp;&amp; (param.length &gt; <xsl:value-of select="@maxOccurs"/>)){
                            throw new java.lang.RuntimeException();
                          }
                      </xsl:if>
                      <xsl:if test="$min!=0">
                          if ((param != null) &amp;&amp; (param.length &lt; <xsl:value-of select="$min"/>)){
                            throw new java.lang.RuntimeException();
                          }
                      </xsl:if>
                  }


                 /**
                  * Auto generated setter method
                  * @param param <xsl:value-of select="$javaName"/>
                  */
                  public void set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/> param){
                   <!-- call the validator-->
                   validate<xsl:value-of select="$javaName"/>(param);

                   <xsl:if test="$choice">
                       clearAllSettingTrackers();
                   </xsl:if>
                   <xsl:if test="$min=0 or $choice">
                       <!-- the updating of setting tracker for null values should
                            happen if the attribute is marked as nillable. Else
                            the user can set a null value and it is never marked
                            as set
                       -->
                      <xsl:choose>
                           <xsl:when test="@primitive and not(@array)">
                               // setting the primitive tracker always true
                               <xsl:value-of select="$settingTracker"/> = true;
                           </xsl:when>
                           <xsl:otherwise>
                               if (param != null){
                                  //update the setting tracker
                                  <xsl:value-of select="$settingTracker"/> = true;
                               } else {
                                  <xsl:choose>
                                      <xsl:when test="@nillable">
                                          <xsl:value-of select="$settingTracker"/> = true;
                                      </xsl:when>
                                      <xsl:otherwise>
                                          <xsl:value-of select="$settingTracker"/> = false;
                                      </xsl:otherwise>
                                  </xsl:choose>
                               }
                           </xsl:otherwise>
                        </xsl:choose>

                   </xsl:if>
                  this.<xsl:value-of select="$varName"/>=param;
                  }

                   <!-- we special case the 'array' scenario and generate a convenience
                       method for adding elements one by one to the array. The
                       current implementation is somewhat inefficient but
                       gets the job done.Since a primitive cannot be
                       treated as an object it has to be ignored!

                 -->
                 <xsl:if test="not(@primitive)">
                 /**
                 * Auto generated add method for the array for convenience
                 * @param param <xsl:value-of select="$basePropertyType"/>
                 */
                 public void add<xsl:value-of select="$javaName"/>(<xsl:value-of select="$basePropertyType"/> param){
                   if (<xsl:value-of select="$varName"/> == null){
                       <xsl:value-of select="$varName"/> = new <xsl:value-of select="$propertyType"/>{};
                   }

                    <xsl:if test="$choice">
                           clearAllSettingTrackers();
                    </xsl:if>
                    <xsl:if test="$min=0 or $choice">
                         //update the setting tracker
                         <xsl:value-of select="$settingTracker"/> = true;
                    </xsl:if>

                   java.util.List list =
                        org.apache.axis2.databinding.utils.ConverterUtil.toList(<xsl:value-of select="$varName"/>);
                   list.add(param);
                   this.<xsl:value-of select="$varName"/> =
                     (<xsl:value-of select="$propertyType"/>)list.toArray(
                        new <xsl:value-of select="$basePropertyType"/>[list.size()]);

                 }
                 </xsl:if>
                     <!-- end of special casing for the array-->

               </xsl:when>
                <!-- Non array setter method-->
                <xsl:otherwise>
                    /**
                   * Auto generated setter method
                   * @param param <xsl:value-of select="$javaName"/>
                   */
                   public void set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/> param){
                    <xsl:if test="$choice">
                        clearAllSettingTrackers();
                    </xsl:if>
                    <xsl:if test="$min=0 or $choice">
                        <xsl:choose>
                           <xsl:when test="@primitive and not(@array)">
                               // setting the primivite tracker to true
                               <xsl:value-of select="$settingTracker"/> = true;
                           </xsl:when>
                           <xsl:otherwise>
                               if (param != null){
                                  //update the setting tracker
                                  <xsl:value-of select="$settingTracker"/> = true;
                               } else {
                                  <xsl:choose>
                                      <xsl:when test="@nillable">
                                          <xsl:value-of select="$settingTracker"/> = true;
                                      </xsl:when>
                                      <xsl:otherwise>
                                          <xsl:value-of select="$settingTracker"/> = false;
                                      </xsl:otherwise>
                                  </xsl:choose>
                               }
                           </xsl:otherwise>
                        </xsl:choose>

                    </xsl:if>
                   this.<xsl:value-of select="$varName"/>=param;
                   }
                </xsl:otherwise>
            </xsl:choose>


             <!-- end of xsl:if for not(@inherited) -->
            </xsl:if>

        </xsl:for-each>

   }
    </xsl:when>
    <xsl:otherwise>
    <!--  Start of helper generation part of the template-->
public <xsl:if test="not(@unwrapped) or (@skip-write)">static</xsl:if> class <xsl:value-of select="$helpername"/> {

     <!-- get OMElement methods that allows direct writing. generated inside the helper class-->
     <xsl:variable name="fullyQualifiedName"><xsl:value-of select="$package"/>.<xsl:value-of select="$name"/></xsl:variable>
     <xsl:variable name="fullyQualifiedHelperName"><xsl:value-of select="$package"/>.<xsl:value-of select="$helpername"/></xsl:variable>
     /**
     *
     * @param parentQName
     * @param factory
     * @return org.apache.axiom.om.OMElement
     */
    public static org.apache.axiom.om.OMElement getOMElement(
            final <xsl:value-of select="$fullyQualifiedName"/> bean,
            final javax.xml.namespace.QName parentQName,
            final org.apache.axiom.om.OMFactory factory){

        org.apache.axiom.om.OMDataSource dataSource =
                       new org.apache.axis2.databinding.ADBHelperDataSource(bean,parentQName,"<xsl:value-of select="$fullyQualifiedHelperName"/>"){
                           public void serialize(
                                  javax.xml.stream.XMLStreamWriter xmlWriter) throws javax.xml.stream.XMLStreamException {

            <xsl:value-of select="$fullyQualifiedName"/> typedBean =
                               (<xsl:value-of select="$fullyQualifiedName"/>)bean;
            <xsl:choose>
            <xsl:when test="@type or @anon">
                <!-- For a type write the passed in QName first-->
                xmlWriter.writeStartElement(parentQName.getNamespaceURI(),
                                            parentQName.getLocalPart());

               <!-- write the type attribute if needed -->
               <xsl:if test="$extension">
               writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","type",
                       registerPrefix(xmlWriter,"<xsl:value-of select="$nsuri"/>")+":<xsl:value-of select="$originalName"/>",
                       xmlWriter);
               </xsl:if>
                <!--First serialize the attributes!-->
                <xsl:for-each select="property[@attribute]">
                    <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                    <xsl:variable name="varName">typedBean.local<xsl:value-of select="@javaname"/></xsl:variable>
                     <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                    <xsl:choose>
                        <!-- Note - It is assumed that any attributes are OMAttributes-->
                        <xsl:when test="@any and not(@array)">
                            writeAttribute(<xsl:value-of select="$varName"/>.getNamespace().getName(),
                                                     <xsl:value-of select="$varName"/>.getLocalName(),
                                                     <xsl:value-of select="$varName"/>.getAttributeValue(),xmlWriter);
                        </xsl:when>
                        <xsl:when test="@any and @array">
                             if (<xsl:value-of select="$varName"/> != null) {
                                 for (int i=0;i &lt;<xsl:value-of select="$varName"/>.length;i++){
                                     writeAttribute(<xsl:value-of select="$varName"/>[i].getNamespace().getName(),
                                                    <xsl:value-of select="$varName"/>[i].getLocalName(),
                                                    <xsl:value-of select="$varName"/>[i].getAttributeValue(),xmlWriter);
                                     }
                             }
                        </xsl:when>
                        <!-- there can never be attribute arrays in the normal case-->
                        <xsl:when test="@optional">
                             // optional attribute <xsl:value-of select="$propertyName"/>
                             try {
                                writeAttribute("<xsl:value-of select="$namespace"/>",
                                               "<xsl:value-of select="$propertyName"/>",
                                               org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>), xmlWriter);
                            } catch (NullPointerException e) {
                                // If <xsl:value-of select="$varName"/> was null
                                // it can not be serialized.
                            }
                        </xsl:when>
                        <xsl:otherwise>
                             writeAttribute("<xsl:value-of select="$namespace"/>",
                                                     "<xsl:value-of select="$propertyName"/>",
                                                      org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>),xmlWriter);
                        </xsl:otherwise>
                    </xsl:choose>
                </xsl:for-each>

                <!-- Now serialize the elements-->
                <xsl:for-each select="property[not(@attribute)]">
                    <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                    <xsl:variable name="varName">typedBean.local<xsl:value-of select="@javaname"/></xsl:variable>
                    <xsl:variable name="min"><xsl:value-of select="@minOccurs"/></xsl:variable>
                    <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                    <xsl:variable name="settingTracker">local<xsl:value-of select="@javaname"/>Tracker</xsl:variable>


                    <xsl:if test="$min=0 or $choice"> if (<xsl:value-of select="$settingTracker"/>){</xsl:if>
                    <xsl:choose>
                        <xsl:when test="@ours and not(@array) and not(@default)">
                            <xsl:choose>
                                <xsl:when test="@nillable">
                                    if (<xsl:value-of select="$varName"/>==null){
                                       xmlWriter.writeStartElement("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>");
                                      // write the nil attribute
                                      writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                                       xmlWriter.writeEndElement();
                                    }else{
                                          <xsl:value-of select="@type"/>Helper.getOMElement(
                                            <xsl:value-of select="$varName"/>,
                                          new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>"),
                                        factory).serialize(xmlWriter);
                                    }
                                </xsl:when>
                                <xsl:otherwise>
                                    if (<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }

                                            <xsl:value-of select="@type"/>Helper.getOMElement(
                                            <xsl:value-of select="$varName"/>,
                                            new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>"),
                                            factory).serialize(xmlWriter);

                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:when>
                        <xsl:when test="@ours and @array and not(@default)">
                             <xsl:choose>
                                <xsl:when test="@nillable">
                                    // this property is nillable
                                    if (<xsl:value-of select="$varName"/>!=null){
                                    <!--this bracket needs to be closed!-->
                                </xsl:when>
                                <xsl:otherwise>
                                    if (<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }
                                </xsl:otherwise>
                            </xsl:choose>

                            for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                                    <xsl:value-of select="@type"/>Helper.getOMElement(
                                    <xsl:value-of select="$varName"/>[i],
                                    new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>"),
                                    factory).serialize(xmlWriter);
                            }
                            <!--we've opened a bracket for the nulls - fix it here-->
                            <xsl:if test="@nillable">}</xsl:if>
                        </xsl:when>

                         <xsl:when test="@default and @array">
                            <!-- Note - Assumed to be OMElement-->
                            <xsl:choose>
                               <xsl:when test="@nillable">
                                    // this property is nillable
                                    if (<xsl:value-of select="$varName"/>!=null){
                                    <!--this bracket needs to be closed!-->
                                </xsl:when>
                                <xsl:otherwise>
                                    if (<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }
                                </xsl:otherwise>
                            </xsl:choose>

                              for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                                  <xsl:value-of select="$varName"/>[i].serialize(xmlWriter);
                              }

                            <!--we've opened a bracket for the nulls - fix it here-->
                            <xsl:if test="@nillable">}</xsl:if>

                        </xsl:when>

                        <xsl:when test="@default and not(@array)">
                            <!-- Note - Assumed to be OMElement-->
                            <xsl:choose>
                             <xsl:when test="@nillable">
                                    // this property is nillable
                                    if (<xsl:value-of select="$varName"/>!=null){
                                    <!--this bracket needs to be closed!-->
                                </xsl:when>
                                <xsl:otherwise>
                                    if (<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }
                                </xsl:otherwise>
                             </xsl:choose>
                             <xsl:value-of select="$varName"/>.serialize(xmlWriter);
                             <xsl:if test="@nillable">}</xsl:if>
                        </xsl:when>
                        <!-- handle non ADB arrays - Not any however -->
                        <xsl:when test="@array and not(@any)">
                             <xsl:choose>
                                <xsl:when test="@nillable">
                                    // this property is nillable
                                    if (<xsl:value-of select="$varName"/>!=null){
                                    <!--this bracket needs to be closed!-->
                                </xsl:when>
                                <xsl:otherwise>
                                    if (<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }
                                </xsl:otherwise>
                            </xsl:choose>
                            for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                              xmlWriter.writeStartElement("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>");
                              if (<xsl:value-of select="$varName"/>[i]==null){
                                  // write the nil attribute
                                  writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);
                              }else{
                                 xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>[i]));
                              }
                              xmlWriter.writeEndElement();
                            }
                            <!--we've opened a bracket for the nulls - fix it here-->
                            <xsl:if test="@nillable">}</xsl:if>
                        </xsl:when>

                         <!-- handle non ADB arrays  - Any case  - any may not be
                         nillable -->
                        <xsl:when test="@array and @any">
                            <!-- Note - Assumed to be OMElement-->
                            for (int i = 0;i &lt; <xsl:value-of select="$varName"/>.length;i++){
                              <xsl:value-of select="$varName"/>[i].serialize(xmlWriter);
                            }
                        </xsl:when>
                        <!-- handle any - non array case-->
                         <xsl:when test="@any">
                            <!-- Note - Assumed to be OMElement-->
                            <xsl:value-of select="$varName"/>.serialize(xmlWriter);
                        </xsl:when>

                        <!-- handle all other cases including the binary case -->
                         <xsl:otherwise>
                            xmlWriter.writeStartElement("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>");
                            xmlWriter.writeCharacters(org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                            xmlWriter.writeEndElement();
                        </xsl:otherwise>
                    </xsl:choose>
                    <xsl:if test="$min=0 or $choice">}</xsl:if>

                </xsl:for-each>
                   <!-- write the end element for the type-->
               xmlWriter.writeEndElement();
            <!-- end of when for type & anon -->
            </xsl:when>


            <!-- Not a type and not anon. So it better be only one inclusion-->
            <xsl:otherwise>
                <!-- if the element is associated with a type, then its gonna be only one -->
                //We can safely assume an element has only one type associated with it
                <xsl:variable name="varName">typedBean.local<xsl:value-of select="property/@javaname"/></xsl:variable>
                <xsl:variable name="nillable" select="property/@nillable"/>
                <xsl:variable name="primitive" select="property/@primitive"/>
                <xsl:variable name="type" select="property/@type"/>

                <xsl:choose>
                    <!-- This better be only one!!-->
                    <xsl:when test="property/@ours">
                        <xsl:choose>
                            <xsl:when test="$nillable">
                                      if (<xsl:value-of select="$varName"/>==null){
                                          xmlWriter.writeStartElement("<xsl:value-of select="property/@namespace"/>","<xsl:value-of select="property/@name"/>");

                                         // write the nil attribute
                                        writeAttribute("xsi","http://www.w3.org/2001/XMLSchema-instance","nil","true",xmlWriter);

                                        xmlWriter.writeEndElement();
                                       }else{
                                         <xsl:value-of select="$type"/>Helper.getOMElement(
                                         <xsl:value-of select="$varName"/>,
                                         <xsl:value-of select="$fullyQualifiedName"/>.MY_QNAME,
                                         factory).serialize(xmlWriter);
                                       }
                            </xsl:when>
                            <xsl:otherwise>
                                 if (<xsl:value-of select="$varName"/>==null){
                                   throw new RuntimeException("Property cannot be null!");
                                 }
                                <xsl:value-of select="$type"/>Helper.getOMElement(
                                         <xsl:value-of select="$varName"/>,
                                         <xsl:value-of select="$fullyQualifiedName"/>.MY_QNAME,
                                         factory).serialize(xmlWriter);
                            </xsl:otherwise>
                        </xsl:choose>
                    </xsl:when>
                    <!-- end of ours block-->
                    <xsl:otherwise>
                       xmlWriter.writeStartElement(
                       "<xsl:value-of select="property/@namespace"/>","<xsl:value-of select="property/@name"/>");
                       xmlWriter.writeCharacters(
                        org.apache.axis2.databinding.utils.ConverterUtil.convertToString(<xsl:value-of select="$varName"/>));
                       xmlWriter.writeEndElement();
                    </xsl:otherwise>
                </xsl:choose>
            </xsl:otherwise>
        </xsl:choose>

        }

         /**
          * Util method to write an attribute with the ns prefix
          */
          private void writeAttribute(java.lang.String prefix,java.lang.String namespace,java.lang.String attName,
                                      java.lang.String attValue,javax.xml.stream.XMLStreamWriter xmlWriter) throws javax.xml.stream.XMLStreamException{
              if (xmlWriter.getPrefix(namespace) == null) {
                       xmlWriter.writeNamespace(prefix, namespace);
                       xmlWriter.setPrefix(prefix, namespace);

              }

              xmlWriter.writeAttribute(namespace,attName,attValue);

         }

          /**
          * Util method to write an attribute without the ns prefix
          */
          private void writeAttribute(java.lang.String namespace,java.lang.String attName,
                                      java.lang.String attValue,javax.xml.stream.XMLStreamWriter xmlWriter) throws javax.xml.stream.XMLStreamException{

    	  	  if (namespace.equals(""))
        	  {
        		  xmlWriter.writeAttribute(attName,attValue);
        	  }
        	  else
        	  {
                  registerPrefix(xmlWriter, namespace);
                  xmlWriter.writeAttribute(namespace,attName,attValue);
              }
          }

         /**
         * Register a namespace prefix
         */
         private java.lang.String registerPrefix(javax.xml.stream.XMLStreamWriter xmlWriter, java.lang.String namespace) throws javax.xml.stream.XMLStreamException {
                java.lang.String prefix = xmlWriter.getPrefix(namespace);

                if (prefix == null) {
                    prefix = createPrefix();

                    while (xmlWriter.getNamespaceContext().getNamespaceURI(prefix) != null) {
                        prefix = createPrefix();
                    }

                    xmlWriter.writeNamespace(prefix, namespace);
                    xmlWriter.setPrefix(prefix, namespace);
                }

                return prefix;
            }

         /**
          * Create a prefix
          */
          private java.lang.String createPrefix() {
                return "ns" + (int)Math.random();
          }
        };

        <xsl:choose>
            <xsl:when test="@type">
               return new org.apache.axiom.om.impl.llom.OMSourcedElementImpl(
               parentQName,factory,dataSource);
            </xsl:when>
            <xsl:otherwise>
               //ignore the QName passed in - we send only OUR QName!
               return new org.apache.axiom.om.impl.llom.OMSourcedElementImpl(
               <xsl:value-of select="$fullyQualifiedName"/>.MY_QNAME,factory,dataSource);
            </xsl:otherwise>
       </xsl:choose>
    }




        /**
        * static method to create the object
        * Precondition:  If this object is an element, the current or next start element starts this object and any intervening reader events are ignorable
        *                If this object is not an element, it is a complex type and the reader is at the event just after the outer start element
        * Postcondition: If this object is an element, the reader is positioned at its end element
        *                If this object is a complex type, the reader is positioned at the end element of its outer element
        */
        public static <xsl:value-of select="$fullyQualifiedName"/> parse(javax.xml.stream.XMLStreamReader reader) throws java.lang.Exception{
            <xsl:value-of select="$fullyQualifiedName"/> object = new <xsl:value-of select="$fullyQualifiedName"/>();
            int event;
            try {
                <!-- Advance to our start element, or if we are a complex type, to our first property start element or the outer end element if no properties -->
                while (!reader.isStartElement() &amp;&amp; !reader.isEndElement())
                    reader.next();

                <xsl:if test="@nillable">
                   if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                         // Skip the element and report the null value.  It cannot have subelements.
                         while (!reader.isEndElement())
                             reader.next();
                         return null;
                   }
                </xsl:if>

                if (reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","type")!=null){
                  java.lang.String fullTypeName = reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance",
                        "type");
                  if (fullTypeName!=null){
                    java.lang.String nsPrefix = fullTypeName.substring(0,fullTypeName.indexOf(":"));
                    nsPrefix = nsPrefix==null?"":nsPrefix;

                    java.lang.String type = fullTypeName.substring(fullTypeName.indexOf(":")+1);

                     if (!"<xsl:value-of select="$originalName"/>".equals(type)){
                        //find namespace for the prefix
                        java.lang.String nsUri = reader.getNamespaceContext().getNamespaceURI(nsPrefix);
                        return (<xsl:value-of select="$name"/>)<xsl:value-of select="$mapperClass"/>.getTypeObject(
                             nsUri,type,reader);
                      }

                  }

                }
                <!-- populate attributes here!!!. The attributes are part of an element, not part of a type -->
                <xsl:for-each select="property[@attribute]">
                    <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                    <xsl:variable name="propertyType" select="@type"/>
                    <xsl:variable name="shortTypeNameUncapped"  select="@shorttypename"/>
                    <xsl:variable name="shortTypeName"
                    select="concat(translate( substring($shortTypeNameUncapped, 1, 1 ),'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' ), substring($shortTypeNameUncapped, 2, string-length($shortTypeNameUncapped)))" />
                    <xsl:variable name="javaName"><xsl:value-of select="@javaname"></xsl:value-of></xsl:variable>
                    <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                    <xsl:variable name="attribName">tempAttrib<xsl:value-of select="$propertyName"/></xsl:variable>

                    java.lang.String <xsl:value-of select="$attribName"/> =
                      reader.getAttributeValue("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>");
                   if (<xsl:value-of select="$attribName"/>!=null){
                    <xsl:choose>
                        <xsl:when test="$propertyType='javax.xml.namespace.QName'">
                            int index = <xsl:value-of select="$attribName"/>.indexOf(":");
                            java.lang.String prefix ="";
                            java.lang.String namespaceuri ="";
                            if(index >0){
                                 prefix = <xsl:value-of select="$attribName"/>.substring(0,index);
                                 namespaceuri = reader.getNamespaceURI(prefix);
                             }
                             object.set<xsl:value-of select="$javaName"/>(
                                  org.apache.axis2.databinding.utils.ConverterUtil.convertToQName(<xsl:value-of select="$attribName"/>,namespaceuri));
                        </xsl:when>
                        <xsl:otherwise>
                         object.set<xsl:value-of select="$javaName"/>(
                           org.apache.axis2.databinding.utils.ConverterUtil.convertTo<xsl:value-of select="$shortTypeName"/>(
                                <xsl:value-of select="$attribName"/>));
                        </xsl:otherwise>
                    </xsl:choose>
                    }

                </xsl:for-each>

                <xsl:if test="$isType or $anon">
                    <!-- Skip the outer start element in order to process the subelements. -->
                    reader.next();
                </xsl:if>
                      <!-- If we are not a type and not an element with anonymous type, then we are an element with one property for our named type. -->
                      <!-- Our single named-type property applies to our entire outer element, so don't skip it. -->
                <!-- First loop creates arrayLists for handling arrays -->
                <xsl:for-each select="property[not(@attribute)]">
                    <xsl:if test="@array">
                        java.util.ArrayList list<xsl:value-of select="position()"/> = new java.util.ArrayList();
                    </xsl:if>
                </xsl:for-each>

                <xsl:if test="property[not(@attribute)]">
                <xsl:if test="$unordered">   <!-- Properties can be in any order -->
                while(!reader.isEndElement()) {
                    if (reader.isStartElement()){
                </xsl:if>
                </xsl:if>

                        <!-- Now reloop and populate the code -->
                        <xsl:for-each select="property[not(@attribute)]">
                            <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                            <xsl:variable name="propertyType"><xsl:value-of select="@type"/></xsl:variable>
                            <xsl:variable name="shortTypeNameUncapped"  select="@shorttypename"/>
                            <xsl:variable name="shortTypeName"
                               select="concat(translate( substring($shortTypeNameUncapped, 1, 1 ),'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' ), substring($shortTypeNameUncapped, 2, string-length($shortTypeNameUncapped)))" />
                            <xsl:variable name="javaName"><xsl:value-of select="@javaname"></xsl:value-of></xsl:variable>
                            <xsl:variable name="listName">list<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="loopBoolName">loopDone<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="startQname">startQname<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="stateMachineName">stateMachine<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="builderName">builder<xsl:value-of select="position()"/></xsl:variable>
                            <xsl:variable name="basePropertyType"><xsl:value-of select="@arrayBaseType"/></xsl:variable>
                            <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                            <xsl:variable name="min"><xsl:value-of select="@minOccurs"/></xsl:variable>

                            <xsl:variable name="propQName">new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>")</xsl:variable>

                           <xsl:choose>
                                <xsl:when test="$unordered">  <!-- One property per iteration if unordered -->
                                    <xsl:if test="position()>1">
                                        else
                                    </xsl:if>
                                </xsl:when>
                                <xsl:otherwise>
                                    <!-- If sequence, advance to start of next property or to end of outer element -->
                                    while (!reader.isStartElement() &amp;&amp; !reader.isEndElement()) reader.next();
                                </xsl:otherwise>
                            </xsl:choose>
                            if (reader.isStartElement() &amp;&amp; <xsl:value-of select="$propQName"/>.equals(reader.getName())){
                            <xsl:choose>
                                <xsl:when test="@array">
                                    <!-- We must be a named type or element with anonymous type. -->
                                    <!-- Elements with a named type have a single simple (non-array) property for their type -->
                                    // Process the array and step past its final element's end.
                                    <xsl:variable name="basePropertyType"><xsl:value-of select="@arrayBaseType"/></xsl:variable>
                                    <xsl:choose>
                                        <xsl:when test="@ours">
                                            <xsl:value-of select="$listName"/>.add(<xsl:value-of select="$basePropertyType"/>Helper.parse(reader));
                                            //loop until we find a start element that is not part of this array
                                            boolean <xsl:value-of select="$loopBoolName"/> = false;
                                            while(!<xsl:value-of select="$loopBoolName"/>){
                                                // We should be at the end element, but make sure
                                                while (!reader.isEndElement())
                                                    reader.next();
                                                // Step out of this element
                                                reader.next();
                                                // Step to next element event.
                                                while (!reader.isStartElement() &amp;&amp; !reader.isEndElement())
                                                    reader.next();
                                                if (reader.isEndElement()){
                                                    //two continuous end elements means we are exiting the xml structure
                                                    <xsl:value-of select="$loopBoolName"/> = true;
                                                } else {
                                                    if (<xsl:value-of select="$propQName"/>.equals(reader.getName())){
                                                        <xsl:value-of select="$listName"/>.add(<xsl:value-of select="$basePropertyType"/>Helper.parse(reader));
                                                    }else{
                                                        <xsl:value-of select="$loopBoolName"/> = true;
                                                    }
                                                }
                                            }
                                            // call the converter utility  to convert and set the array
                                            object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                    <xsl:value-of select="$basePropertyType"/>.class,
                                                    <xsl:value-of select="$listName"/>));
                                        </xsl:when>

                                        <!--Let's handle xs:any here-->
                                        <xsl:when test="$shortTypeName='OMElement'">
                                           boolean <xsl:value-of select="$loopBoolName"/>=false;

                                             while (!<xsl:value-of select="$loopBoolName"/>){
                                                 event = reader.getEventType();
                                                 if (javax.xml.stream.XMLStreamConstants.START_ELEMENT == event){

                                                      <!-- if-block that handles nillable -->
                                                      <xsl:if test="@nillable">
                                                          if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                              <xsl:value-of select="$listName"/>.add(null);
                                                          }else{
                                                      </xsl:if>

                                                      // We need to wrap the reader so that it produces a fake START_DOCUEMENT event
                                                      org.apache.axis2.databinding.utils.NamedStaxOMBuilder <xsl:value-of select="$builderName"/>
                                                         = new org.apache.axis2.databinding.utils.NamedStaxOMBuilder(
                                                              new org.apache.axis2.util.StreamWrapper(reader), reader.getName());

                                                       <xsl:value-of select="$listName"/>.add(<xsl:value-of select="$builderName"/>.getOMElement());
                                                       <xsl:if test="@nillable">}</xsl:if>
                                                 } else if (javax.xml.stream.XMLStreamConstants.START_ELEMENT == event){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else if (javax.xml.stream.XMLStreamConstants.END_ELEMENT == event){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else if (javax.xml.stream.XMLStreamConstants.END_DOCUMENT == event){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else{
                                                     reader.next();
                                                 }

                                             }

                                             object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                 org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                     <xsl:value-of select="$basePropertyType"/>.class,<xsl:value-of select="$listName"/>));
                                        </xsl:when>


                                        <xsl:otherwise>
                                            <xsl:choose>

                                        <!-- End of Array handling of ADB classes -->
                                        <xsl:when test="@default">
                                             boolean <xsl:value-of select="$loopBoolName"/>=false;
                                             javax.xml.namespace.QName <xsl:value-of select="$startQname"/> = new javax.xml.namespace.QName(
                                                    "<xsl:value-of select="$namespace"/>",
                                                    "<xsl:value-of select="$propertyName"/>");

                                             while (!<xsl:value-of select="$loopBoolName"/>){
                                                 event = reader.getEventType();
                                                 if (javax.xml.stream.XMLStreamConstants.START_ELEMENT == event
                                                         &amp;&amp; <xsl:value-of select="$startQname"/>.equals(reader.getName())){

                                                      <!-- if-block that handles nillable -->
                                                      <xsl:if test="@nillable">
                                                          if ("true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                                              <xsl:value-of select="$listName"/>.add(null);
                                                          }else{
                                                      </xsl:if>

                                                      // We need to wrap the reader so that it produces a fake START_DOCUEMENT event
                                                      org.apache.axis2.databinding.utils.NamedStaxOMBuilder <xsl:value-of select="$builderName"/>
                                                         = new org.apache.axis2.databinding.utils.NamedStaxOMBuilder(
                                                              new org.apache.axis2.util.StreamWrapper(reader), <xsl:value-of select="$startQname"/>);

                                                       <xsl:value-of select="$listName"/>.add(<xsl:value-of select="$builderName"/>.getOMElement());
                                                       <xsl:if test="@nillable">}</xsl:if>
                                                 } else if (javax.xml.stream.XMLStreamConstants.START_ELEMENT == event &amp;&amp;
                                                            !<xsl:value-of select="$startQname"/>.equals(reader.getName())){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else if (javax.xml.stream.XMLStreamConstants.END_ELEMENT == event &amp;&amp;
                                                           !<xsl:value-of select="$startQname"/>.equals(reader.getName())){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else if (javax.xml.stream.XMLStreamConstants.END_DOCUMENT == event){
                                                     <xsl:value-of select="$loopBoolName"/> = true;
                                                 }else{
                                                     reader.next();
                                                 }

                                             }

                                             object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                 org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                     <xsl:value-of select="$basePropertyType"/>.class,<xsl:value-of select="$listName"/>));

                                        </xsl:when>
                                        <!-- End of Array handling of default class - that is the OMElement -->
                                        <xsl:otherwise>
                                            <xsl:value-of select="$listName"/>.add(reader.getElementText());
                                            //loop until we find a start element that is not part of this array
                                            boolean <xsl:value-of select="$loopBoolName"/> = false;
                                            while(!<xsl:value-of select="$loopBoolName"/>){
                                                // Ensure we are at the EndElement
                                                while (!reader.isEndElement()){
                                                    reader.next();
                                                }
                                                // Step out of this element
                                                reader.next();
                                                // Step to next element event.
                                                while (!reader.isStartElement() &amp;&amp; !reader.isEndElement())
                                                    reader.next();
                                                if (reader.isEndElement()){
                                                    //two continuous end elements means we are exiting the xml structure
                                                    <xsl:value-of select="$loopBoolName"/> = true;
                                                } else {
                                                    if (<xsl:value-of select="$propQName"/>.equals(reader.getName())){
                                                        <xsl:value-of select="$listName"/>.add(reader.getElementText());
                                                    }else{
                                                        <xsl:value-of select="$loopBoolName"/> = true;
                                                    }
                                                }
                                            }
                                            // call the converter utility  to convert and set the array
                                            object.set<xsl:value-of select="$javaName"/>((<xsl:value-of select="$propertyType"/>)
                                                org.apache.axis2.databinding.utils.ConverterUtil.convertToArray(
                                                    <xsl:value-of select="$basePropertyType"/>.class,
                                                    <xsl:value-of select="$listName"/>));
                                        </xsl:otherwise>
                                    </xsl:choose>

                                    </xsl:otherwise>
                                    </xsl:choose>
                                </xsl:when>
                                <xsl:when test="@ours">
                                    object.set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$propertyType"/>Helper.parse(reader));
                                    <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                        reader.next();
                                    </xsl:if>
                                </xsl:when>
                                <!-- start of any handling. Any can also be @default so we need to handle the any case before default! -->
                                <xsl:when test="@any">
                                    <!--No concerns of being nillable here. if it's ours and if the nillable attribute was present
                                        we would have outputted a null already-->
                                     <!--This can be any element and we may not know the name. so we pick the name of the element from the parser-->
                                     //use the QName from the parser as the name for the builder
                                     javax.xml.namespace.QName <xsl:value-of select="$startQname"/> = reader.getName();

                                     // We need to wrap the reader so that it produces a fake START_DOCUMENT event
                                     // this is needed by the builder classes
                                     org.apache.axis2.databinding.utils.NamedStaxOMBuilder <xsl:value-of select="$builderName"/> =
                                         new org.apache.axis2.databinding.utils.NamedStaxOMBuilder(
                                             new org.apache.axis2.util.StreamWrapper(reader),<xsl:value-of select="$startQname"/>);
                                     object.set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$builderName"/>.getOMElement());
                                     <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                         reader.next();
                                     </xsl:if>
                                </xsl:when>
                                <!-- end of adb type handling code -->
                                <!-- start of OMelement handling -->
                                 <xsl:when test="@default">
                                     boolean <xsl:value-of select="$loopBoolName"/> = false;
                                     javax.xml.namespace.QName <xsl:value-of select="$startQname"/> = new javax.xml.namespace.QName(
                                                                         "<xsl:value-of select="$namespace"/>",
                                                                         "<xsl:value-of select="$propertyName"/>");

                                     while(!<xsl:value-of select="$loopBoolName"/>){
                                         if (reader.isStartElement() &amp;&amp; <xsl:value-of select="$startQname"/>.equals(reader.getName())){
                                             <xsl:value-of select="$loopBoolName"/> = true;
                                         }else{
                                             reader.next();
                                         }
                                     }

                                     <!-- todo  put the code here for nillable -->
                                     // We need to wrap the reader so that it produces a fake START_DOCUEMENT event
                                     // this is needed by the builder classes
                                     org.apache.axis2.databinding.utils.NamedStaxOMBuilder <xsl:value-of select="$builderName"/> =
                                         new org.apache.axis2.databinding.utils.NamedStaxOMBuilder(
                                             new org.apache.axis2.util.StreamWrapper(reader),<xsl:value-of select="$startQname"/>);
                                     object.set<xsl:value-of select="$javaName"/>(<xsl:value-of select="$builderName"/>.getOMElement());
                                     <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                         reader.next();
                                     </xsl:if>
                                </xsl:when>
                                <!-- end of OMelement handling -->
                                <!-- start of the simple types handling for binary content-->
                                <xsl:when test="@binary">
                                    if (isReaderMTOMAware(reader)
                                            &amp;&amp;
                                            java.lang.Boolean.TRUE.equals(reader.getProperty(org.apache.axiom.om.OMConstants.IS_BINARY)))
                                    {
                                        //MTOM aware reader - get the datahandler directly and put it in the object
                                        object.set<xsl:value-of select="$javaName"/>(
                                                (javax.activation.DataHandler) reader.getProperty(org.apache.axiom.om.OMConstants.DATA_HANDLER));
                                    } else {
                                        if (reader.getEventType() == javax.xml.stream.XMLStreamConstants.START_ELEMENT &amp;&amp; reader.getName().equals(new javax.xml.namespace.QName(org.apache.axiom.om.impl.MTOMConstants.XOP_NAMESPACE_URI, org.apache.axiom.om.impl.MTOMConstants.XOP_INCLUDE)))
                                        {
                                            java.lang.String id = org.apache.axiom.om.util.ElementHelper.getContentID(reader, "UTF-8");
                                            object.set<xsl:value-of select="$javaName"/>(((org.apache.axiom.soap.impl.builder.MTOMStAXSOAPModelBuilder) ((org.apache.axiom.om.impl.llom.OMStAXWrapper) reader).getBuilder()).getDataHandler(id));
                                            reader.next();
                                        } else if(reader.hasText()) {
                                            //Do the usual conversion
                                            java.lang.String content = reader.getText();
                                            object.set<xsl:value-of select="$javaName"/>(
                                                    org.apache.axis2.databinding.utils.ConverterUtil.convertToBase64Binary(content));
                                        }
                                    }
                                    <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                        reader.next();
                                    </xsl:if>
                                </xsl:when>
                                <!-- start of the simple types handling -->
                                <xsl:otherwise>
                                    <xsl:if test="@nillable">
                                       if (!"true".equals(reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance","nil"))){
                                    </xsl:if>
                                    java.lang.String content = reader.getElementText();
                                    <xsl:choose>
                                        <xsl:when test="$propertyType='javax.xml.namespace.QName'">
                                            int index = content.indexOf(":");
                                            java.lang.String prefix ="";
                                            java.lang.String namespaceuri ="";
                                            if(index >0){
                                                 prefix = content.substring(0,index);
                                                 namespaceuri = reader.getNamespaceURI(prefix);
                                             }
                                             object.set<xsl:value-of select="$javaName"/>(
                                                  org.apache.axis2.databinding.utils.ConverterUtil.convertToQName(content,namespaceuri));
                                        </xsl:when>
                                        <xsl:when test="$propertyType='org.apache.axiom.om.OMElement'">
                                            org.apache.axiom.om.OMFactory fac = org.apache.axiom.om.OMAbstractFactory.getOMFactory();
                                            org.apache.axiom.om.OMNamespace omNs = fac.createOMNamespace("<xsl:value-of select="$namespace"/>", "");
                                            org.apache.axiom.om.OMElement _value<xsl:value-of select="$javaName"/> = fac.createOMElement("<xsl:value-of select="$propertyName"/>", omNs);
                                            _value<xsl:value-of select="$javaName"/>.addChild(fac.createOMText(_value<xsl:value-of select="$javaName"/>, content));
                                            object.set<xsl:value-of select="$javaName"/>(_value<xsl:value-of select="$javaName"/>);
                                        </xsl:when>
                                        <xsl:otherwise>
                                              object.set<xsl:value-of select="$javaName"/>(
                                        org.apache.axis2.databinding.utils.ConverterUtil.convertTo<xsl:value-of select="$shortTypeName"/>(content));
                                        </xsl:otherwise>
                                    </xsl:choose>
                                    <xsl:if test="@nillable">
                                        } else {
                                            reader.getElementText(); // throw away text nodes if any.
                                        }
                                    </xsl:if>

                                    <xsl:if test="$isType or $anon">  <!-- This is a subelement property to be consumed -->
                                        reader.next();
                                    </xsl:if>
                                </xsl:otherwise>
                            </xsl:choose>

                              }  // End of if for expected property start element

                            <xsl:if test="$ordered and $min!=0">
                                else{
                                    // A start element we are not expecting indicates an invalid parameter was passed
                                    throw new java.lang.RuntimeException("Unexpected subelement " + reader.getLocalName());
                                }
                            </xsl:if>
                        </xsl:for-each>

                        <xsl:if test="$ordered">  <!-- pick up trailing cruft after final property before outer endElement and verify no trailing properties -->
                            while (!reader.isStartElement() &amp;&amp; !reader.isEndElement())
                                reader.next();
                            if (reader.isStartElement())
                                // A start element we are not expecting indicates a trailing invalid property
                                throw new java.lang.RuntimeException("Unexpected subelement " + reader.getLocalName());
                        </xsl:if>

                        <xsl:if test="property[not(@attribute)]">  <!-- this if is needed to skip all this when there are no propoerties-->
                        <xsl:if test="$unordered">
                             else{
                                        // A start element we are not expecting indicates an invalid parameter was passed
                                        throw new java.lang.RuntimeException("Unexpected subelement " + reader.getLocalName());
                             }
                             } else reader.next();  <!-- At neither a start nor an end element, skip it -->
                            }  // end of while loop
                            </xsl:if>
                          </xsl:if>


            } catch (javax.xml.stream.XMLStreamException e) {
                throw new java.lang.Exception(e);
            }

            return object;
        }

        /**
        * isReaderMTOMAware
        * @return true if the reader supports MTOM
        */
      public static boolean isReaderMTOMAware(javax.xml.stream.XMLStreamReader reader) {
           boolean isReaderMTOMAware = false;
           <!-- workaround for the issues in the wstx reader!-->
           try{
             isReaderMTOMAware = java.lang.Boolean.TRUE.equals(reader.getProperty(org.apache.axiom.om.OMConstants.IS_DATA_HANDLERS_AWARE));
           }catch(java.lang.IllegalArgumentException e){
             isReaderMTOMAware = false;
           }
           return isReaderMTOMAware;
      }

     public static javax.xml.stream.XMLStreamReader getPullParser(java.lang.Object beanObject, javax.xml.namespace.QName qName){

        <xsl:value-of select="@package"/>.<xsl:value-of select="@name"/> bean =
         (<xsl:value-of select="@package"/>.<xsl:value-of select="@name"/>)beanObject;

        <xsl:choose>
            <xsl:when test="@type or @anon">
                 java.util.ArrayList elementList = new java.util.ArrayList();
                 java.util.ArrayList attribList = new java.util.ArrayList();

                <xsl:for-each select="property[not(@attribute)]">
                    <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                    <xsl:variable name="varName">local<xsl:value-of select="@javaname"/></xsl:variable>
                    <xsl:variable name="min"><xsl:value-of select="@minOccurs"/></xsl:variable>
                    <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                    <xsl:variable name="settingTracker">local<xsl:value-of select="@javaname"/>Tracker</xsl:variable>


                    <xsl:if test="$min=0 or $choice"> if (<xsl:value-of select="$settingTracker"/>){</xsl:if>
                    <xsl:choose>
                        <xsl:when test="(@ours or @default) and not(@array)">
                            elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                      "<xsl:value-of select="$propertyName"/>"));
                            <!-- Arraylist can handle null's -->
                            <xsl:choose>
                                <xsl:when test="@nillable">
                                    elementList.add(bean.<xsl:value-of select="$varName"/>==null?null:
                                    bean.<xsl:value-of select="$varName"/>);
                                </xsl:when>
                                <xsl:otherwise>
                                    if (bean.<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }
                                    elementList.add(bean.<xsl:value-of select="$varName"/>);
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:when>
                        <xsl:when test="(@ours or @default) and @array">
                             <xsl:choose>
                                <xsl:when test="@nillable">
                                    // this property is nillable
                                    if (bean.<xsl:value-of select="$varName"/>!=null){
                                    <!--this barcket needs to be closed!-->
                                </xsl:when>
                                <xsl:otherwise>
                                    if (bean.<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }
                                </xsl:otherwise>
                            </xsl:choose>
                            for (int i = 0;i &lt; bean.<xsl:value-of select="$varName"/>.length;i++){
                              elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                      "<xsl:value-of select="$propertyName"/>"));
                               elementList.add(bean.<xsl:value-of select="$varName"/>[i]);
                            }
                            <!--we've opened a bracket for the nulls - fix it here-->
                            <xsl:if test="@nillable">}</xsl:if>
                        </xsl:when>
                        <!-- handle non ADB arrays - Not any however -->
                        <xsl:when test="@array and not(@any)">
                             <xsl:choose>
                                <xsl:when test="@nillable">
                                    // this property is nillable
                                    if (bean.<xsl:value-of select="$varName"/>!=null){
                                    <!--this bracket needs to be closed!-->
                                </xsl:when>
                                <xsl:otherwise>
                                    if (bean.<xsl:value-of select="$varName"/>==null){
                                         throw new RuntimeException("<xsl:value-of select="$propertyName"/> cannot be null!!");
                                    }
                                </xsl:otherwise>
                            </xsl:choose>
                            for (int i = 0;i &lt; bean.<xsl:value-of select="$varName"/>.length;i++){
                              elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                      "<xsl:value-of select="$propertyName"/>"));
                              elementList.add(
                              org.apache.axis2.databinding.utils.ConverterUtil.convertToString(bean.<xsl:value-of select="$varName"/>[i]));
                            }
                            <!--we've opened a bracket for the nulls - fix it here-->
                            <xsl:if test="@nillable">}</xsl:if>
                        </xsl:when>

                         <!-- handle non ADB arrays  - Any case  - any may not be
                         nillable -->
                        <xsl:when test="@array and @any">
                            for (int i = 0;i &lt; bean.<xsl:value-of select="$varName"/>.length;i++){
                              elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                      "<xsl:value-of select="$propertyName"/>"));
                              elementList.add(
                              org.apache.axis2.databinding.utils.ConverterUtil.convertToString(bean.<xsl:value-of select="$varName"/>[i]));
                            }
                            <!--we've opened a bracket for the nulls - fix it here-->
                        </xsl:when>
                        <!-- handle any - non array case-->
                         <xsl:when test="@any">
                            elementList.add(org.apache.axis2.databinding.utils.Constants.OM_ELEMENT_KEY);
                            elementList.add(bean.<xsl:value-of select="$varName"/>);
                        </xsl:when>
                        <!-- handle binary - Since it is a Datahandler, we can just add it to the list
                          and the ADB pullparser would handle it right-->
                         <xsl:when test="@binary">
                            elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                      "<xsl:value-of select="$propertyName"/>"));
                            elementList.add(bean.<xsl:value-of select="$varName"/>);
                        </xsl:when>
                        <!-- the usual case!!!!-->
                        <xsl:otherwise>
                             elementList.add(new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>",
                                                                      "<xsl:value-of select="$propertyName"/>"));
                            <xsl:choose>
                                <xsl:when test="@nillable and not(@primitive)">
                                    elementList.add(bean.<xsl:value-of select="$varName"/>==null?null:
                                     org.apache.axis2.databinding.utils.ConverterUtil.convertToString(bean.<xsl:value-of select="$varName"/>));
                                </xsl:when>
                                <xsl:otherwise>
                                elementList.add(
                                   org.apache.axis2.databinding.utils.ConverterUtil.convertToString(bean.<xsl:value-of select="$varName"/>));
                                </xsl:otherwise>
                            </xsl:choose>
                        </xsl:otherwise>
                    </xsl:choose>
                    <xsl:if test="$min=0 or $choice">}</xsl:if>
                </xsl:for-each>

                <xsl:for-each select="property[@attribute]">
                    <xsl:variable name="propertyName"><xsl:value-of select="@name"/></xsl:variable>
                    <xsl:variable name="varName">local<xsl:value-of select="@javaname"/></xsl:variable>
                     <xsl:variable name="namespace"><xsl:value-of select="@nsuri"/></xsl:variable>
                    <xsl:choose>
                        <xsl:when test="@any and not(@array)">
                            attribList.add(org.apache.axis2.databinding.utils.Constants.OM_ATTRIBUTE_KEY);
                            attribList.add(bean.<xsl:value-of select="$varName"/>);
                        </xsl:when>
                         <xsl:when test="@any and @array">
                             for (int i=0;i &lt;bean.<xsl:value-of select="$varName"/>.length;i++){
                               attribList.add(org.apache.axis2.databinding.utils.Constants.OM_ATTRIBUTE_KEY);
                               attribList.add(bean.<xsl:value-of select="$varName"/>[i]);
                             }
                         </xsl:when>
                        <xsl:otherwise>
                            attribList.add(
                            new javax.xml.namespace.QName("<xsl:value-of select="$namespace"/>","<xsl:value-of select="$propertyName"/>"));
                            attribList.add(
                            org.apache.axis2.databinding.utils.ConverterUtil.convertToString(bean.<xsl:value-of select="$varName"/>));
                        </xsl:otherwise>
                    </xsl:choose>
                </xsl:for-each>

                return new org.apache.axis2.databinding.utils.reader.ADBXMLStreamReaderImpl(qName, elementList.toArray(), attribList.toArray());
            <!-- end of when for type & anon -->
            </xsl:when>
            <!-- Not a type and not anon. So it better be only one inclusion-->
            <xsl:otherwise>
                <!-- if the element is associated with a type, then its gonna be only one -->
                //We can safely assume an element has only one type associated with it
                <xsl:variable name="varName">local<xsl:value-of select="property/@javaname"/></xsl:variable>
                <xsl:variable name="nillable" select="property/@nillable"></xsl:variable>
                <xsl:variable name="primitive" select="property/@primitive"></xsl:variable>

                <xsl:choose>
                    <!-- This better be only one!!-->
                    <xsl:when test="property/@ours">

                        <xsl:choose>
                            <xsl:when test="$nillable">
                                if (bean.<xsl:value-of select="$varName"/>==null){
                                   return new org.apache.axis2.databinding.utils.reader.NullXMLStreamReader(bean.MY_QNAME);
                                }else{
                                   return <xsl:value-of select="property/@type"/>Helper.getPullParser(bean.<xsl:value-of select="$varName"/>, bean.MY_QNAME);
                                }
                            </xsl:when>
                            <xsl:otherwise>return <xsl:value-of select="property/@type"/>Helper.getPullParser(bean.<xsl:value-of select="$varName"/>, bean.MY_QNAME);</xsl:otherwise>
                        </xsl:choose>
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:choose>
                            <xsl:when test="$nillable and not($primitive)">
                                if (bean.<xsl:value-of select="$varName"/>==null){
                                      return new org.apache.axis2.databinding.utils.reader.NullXMLStreamReader(bean.MY_QNAME);
                                }else{
                                   return new org.apache.axis2.databinding.utils.reader.ADBXMLStreamReaderImpl(bean.MY_QNAME,
                                       new java.lang.Object[]{
                                      org.apache.axis2.databinding.utils.reader.ADBXMLStreamReader.ELEMENT_TEXT,
                                       org.apache.axis2.databinding.utils.ConverterUtil.convertToString(bean.<xsl:value-of select="$varName"/>)
                                       },
                                       null);
                                }
                            </xsl:when>
                            <xsl:otherwise> return new org.apache.axis2.databinding.utils.reader.ADBXMLStreamReaderImpl(bean.MY_QNAME,
                            new java.lang.Object[]{
                            org.apache.axis2.databinding.utils.reader.ADBXMLStreamReader.ELEMENT_TEXT,
                            org.apache.axis2.databinding.utils.ConverterUtil.convertToString(bean.<xsl:value-of select="$varName"/>)
                            },
                            null);</xsl:otherwise>
                        </xsl:choose>
                    </xsl:otherwise>
                </xsl:choose>
            </xsl:otherwise>
        </xsl:choose>

        }

}
    </xsl:otherwise>
    </xsl:choose>
           <!-- end of main template -->
  </xsl:template>

  <xsl:template match="mapper">
        <xsl:variable name="name" select="@name"/>
        <xsl:variable name="helperMode" select="@helpermode"/>

         <xsl:if test="not(not(@unwrapped) or (@skip-write))">
            /**
            * <xsl:value-of select="$name"/>.java
            *
            * This file was auto-generated from WSDL
            * by the Apache Axis2 version: #axisVersion# #today#
            */

            package <xsl:value-of select="@package"/>;
            /**
            *  <xsl:value-of select="$name"/> class
            */
        </xsl:if>
        public <xsl:if test="not(@unwrapped) or (@skip-write)">static</xsl:if> class <xsl:value-of select="$name"/>{

          public static java.lang.Object getTypeObject(java.lang.String namespaceURI,
                                                       java.lang.String typeName,
                                                       javax.xml.stream.XMLStreamReader reader) throws java.lang.Exception{

              <xsl:for-each select="type">
                  if (
                  "<xsl:value-of select="@nsuri"/>".equals(namespaceURI) &amp;&amp;
                  "<xsl:value-of select="@shortname"/>".equals(typeName)){
                   <xsl:choose>
                       <xsl:when test="$helperMode">
                           return  <xsl:value-of select="@classname"/>Helper.parse(reader);
                       </xsl:when>
                        <xsl:otherwise>
                            return  <xsl:value-of select="@classname"/>.Factory.parse(reader);
                        </xsl:otherwise>
                   </xsl:choose>

                  }

              </xsl:for-each>
             throw new java.lang.RuntimeException("Unsupported type " + namespaceURI + " " + typeName);
          }

        }
    </xsl:template>
</xsl:stylesheet>
