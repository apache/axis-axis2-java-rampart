/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.axis2.wsdl.codegen.emitter;

import org.apache.axis2.databinding.types.*;
import org.apache.axis2.namespace.Constants;

import javax.xml.namespace.QName;
import java.util.Map;
import java.util.HashMap;

/**
 * The java type map. uses a static map for caching
 * Most code from Axis 1 Codebase*
 * Most code JavaTypeMap
 */
public class CTypeInfo extends Constants{

    public static Map getTypeMap() {
        return CTypeInfo.typeMap;
    }

    private static Map typeMap = new HashMap();

    static {
        // If SOAP 1.1 over the wire, map wrapper classes to XSD primitives.
        CTypeInfo.addTypemapping(XSD_STRING,
                "axis2_char_t*");

        // The XSD Primitives are mapped to java primitives.
        CTypeInfo.addTypemapping(XSD_BOOLEAN,"axis2_bool_t");
        //CTypeMap.addTypemapping(XSD_DOUBLE, double.class.getName());
        CTypeInfo.addTypemapping(XSD_FLOAT, "float");
        CTypeInfo.addTypemapping(XSD_INT, "int");
        CTypeInfo.addTypemapping(XSD_INTEGER,
                "int");
        CTypeInfo.addTypemapping(XSD_LONG, "long");
        CTypeInfo.addTypemapping(XSD_SHORT, "short");
        CTypeInfo.addTypemapping(XSD_BYTE, "byte");
        CTypeInfo.addTypemapping(XSD_ANY,  "axiom_node_t*");
        CTypeInfo.addTypemapping(XSD_DECIMAL, "int");

        //anytype is mapped to the OMElement instead of the java.lang.Object
        CTypeInfo.addTypemapping(XSD_ANYTYPE,
                "axiom_node_t*");

        //Qname maps to  jax rpc QName class
        CTypeInfo.addTypemapping(XSD_QNAME,
                "axis2_qname_t*");

        //xsd Date is mapped to the java.util.date!
        CTypeInfo.addTypemapping(XSD_DATE,
                "axis2_date_time_t*");

        // Mapping for xsd:time.  Map to Axis type Time
        CTypeInfo.addTypemapping(XSD_TIME,
                "axis2_date_time_t*");
        CTypeInfo.addTypemapping(XSD_DATETIME,
                "axis2_date_time_t*");

        //as for the base 64 encoded binary stuff we map it to a javax.
        // activation.Datahandler object
        CTypeInfo.addTypemapping(XSD_BASE64,
                "void*");

        CTypeInfo.addTypemapping(XSD_HEXBIN,
                "void*");

        // These are the g* types (gYearMonth, etc) which map to Axis types
        CTypeInfo.addTypemapping(XSD_YEARMONTH,
                "int");
        CTypeInfo.addTypemapping(XSD_YEAR,
                "int");
        CTypeInfo.addTypemapping(XSD_MONTH,
                "int");
        CTypeInfo.addTypemapping(XSD_DAY,
                "int");
        CTypeInfo.addTypemapping(XSD_MONTHDAY,
                "int");

        // xsd:token
        CTypeInfo.addTypemapping(XSD_TOKEN, Token.class.getName());

        // a xsd:normalizedString
        CTypeInfo.addTypemapping(XSD_NORMALIZEDSTRING,
                "axis2_char*");

        // a xsd:unsignedLong
        CTypeInfo.addTypemapping(XSD_UNSIGNEDLONG,
                "unsigned long");

        // a xsd:unsignedInt
        CTypeInfo.addTypemapping(XSD_UNSIGNEDINT,
                "unsigned int");

        // a xsd:unsignedShort
        CTypeInfo.addTypemapping(XSD_UNSIGNEDSHORT,
                "unsigned short");

        // a xsd:unsignedByte
        CTypeInfo.addTypemapping(XSD_UNSIGNEDBYTE,
                "unsinged char");

        // a xsd:nonNegativeInteger
        CTypeInfo.addTypemapping(XSD_NONNEGATIVEINTEGER,
                "unsinged int");

        // a xsd:negativeInteger
        CTypeInfo.addTypemapping(XSD_NEGATIVEINTEGER,
                "int");

        // a xsd:positiveInteger
        CTypeInfo.addTypemapping(XSD_POSITIVEINTEGER,
                "unsinged int");

        // a xsd:nonPositiveInteger
        CTypeInfo.addTypemapping(XSD_NONPOSITIVEINTEGER,
                "int");

        // a xsd:Name
        CTypeInfo.addTypemapping(XSD_NAME, Name.class.getName());

        // a xsd:NCName
        CTypeInfo.addTypemapping(XSD_NCNAME, NCName.class.getName());

        // a xsd:ID
        CTypeInfo.addTypemapping(XSD_ID, Id.class.getName());

        // a xml:lang
        // addTypemapping(XML_LANG,Language.class.getName());

        // a xsd:language
        CTypeInfo.addTypemapping(XSD_LANGUAGE, Language.class.getName());

        // a xsd:NmToken
        CTypeInfo.addTypemapping(XSD_NMTOKEN, NMToken.class.getName());

        // a xsd:NmTokens
        CTypeInfo.addTypemapping(XSD_NMTOKENS, NMTokens.class.getName());

        // a xsd:NOTATION
        CTypeInfo.addTypemapping(XSD_NOTATION, Notation.class.getName());

        // a xsd:XSD_ENTITY
        CTypeInfo.addTypemapping(XSD_ENTITY, Entity.class.getName());

        // a xsd:XSD_ENTITIES
        CTypeInfo.addTypemapping(XSD_ENTITIES, Entities.class.getName());

        // a xsd:XSD_IDREF
        CTypeInfo.addTypemapping(XSD_IDREF, IDRef.class.getName());

        // a xsd:XSD_XSD_IDREFS
        CTypeInfo.addTypemapping(XSD_IDREFS, IDRefs.class.getName());

        // a xsd:Duration
        CTypeInfo.addTypemapping(XSD_DURATION, Duration.class.getName());

        // a xsd:anyURI
        CTypeInfo.addTypemapping(XSD_ANYURI, URI.class.getName());


    }

    private static void addTypemapping(QName name, String str) {
        CTypeInfo.typeMap.put(name, str);
    }


}
