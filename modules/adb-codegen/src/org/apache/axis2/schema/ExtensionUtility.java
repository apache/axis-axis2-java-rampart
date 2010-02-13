package org.apache.axis2.schema;

import org.apache.axis2.description.AxisMessage;
import org.apache.axis2.description.AxisOperation;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.wsdl.WSDLConstants;
import org.apache.axis2.wsdl.WSDLUtil;
import org.apache.axis2.wsdl.codegen.CodeGenConfiguration;
import org.apache.axis2.wsdl.databinding.DefaultTypeMapper;
import org.apache.axis2.wsdl.databinding.JavaTypeMapper;
import org.apache.axis2.wsdl.databinding.TypeMapper;
import org.apache.axis2.wsdl.util.Constants;
import org.apache.ws.commons.schema.*;

import javax.xml.namespace.QName;
import java.io.File;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
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

/**
 * This is the utility for the extension to call by reflection.
 */
public class ExtensionUtility {


    public static void invoke(CodeGenConfiguration configuration) throws Exception {
        List schemaList = configuration.getAxisService().getSchema();

        //hashmap that keeps the targetnamespace and the xmlSchema object
        //this is a convenience to locate the relevant schema quickly
        //by looking at the target namespace
        Map schemaMap = new HashMap();
        populateSchemaMap(schemaMap, schemaList);

        if (schemaList == null || schemaList.isEmpty()) {
            //there are no types to be code generated
            //However if the type mapper is left empty it will be a problem for the other
            //processes. Hence the default type mapper is set to the configuration
            configuration.setTypeMapper(new DefaultTypeMapper());
            return;
        }
        //call the schema compiler
        CompilerOptions options = new CompilerOptions();

        //set the default options
        populateDefaultOptions(options, configuration);

        //set the user parameters. the user parameters get the preference over
        //the default ones. But the user better know what he's doing if he
        //used module specific parameters
        populateUserparameters(options, configuration);

        SchemaCompiler schemaCompiler = new SchemaCompiler(options);
        // run the schema compiler
        schemaCompiler.compile(schemaList);

        //create the type mapper
        //First try to take the one that is already there
        TypeMapper mapper = configuration.getTypeMapper();
        if (mapper == null) {
            mapper = new JavaTypeMapper();
        }

        if (options.isWriteOutput()) {
            //get the processed element map and transfer it to the type mapper
            Map processedMap = schemaCompiler.getProcessedElementMap();
            Iterator processedkeys = processedMap.keySet().iterator();
            QName qNameKey;
            while (processedkeys.hasNext()) {
                qNameKey = (QName) processedkeys.next();
                mapper.addTypeMappingName(qNameKey, processedMap.get(qNameKey).toString());
            }

        } else {
            //get the processed model map and transfer it to the type mapper
            //since the options mentiond that its not writable, it should have
            //populated the model map
            Map processedModelMap = schemaCompiler.getProcessedModelMap();
            Iterator processedkeys = processedModelMap.keySet().iterator();
            QName qNameKey;
            while (processedkeys.hasNext()) {
                qNameKey = (QName) processedkeys.next();
                mapper.addTypeMappingObject(qNameKey, processedModelMap.get(qNameKey));
            }

            Map processedMap = schemaCompiler.getProcessedElementMap();
            processedkeys = processedMap.keySet().iterator();
            while (processedkeys.hasNext()) {
                qNameKey = (QName) processedkeys.next();
                mapper.addTypeMappingName(qNameKey, processedMap.get(qNameKey).toString());
            }

            //get the ADB template from the schema compilers property bag and set the
            //template
            configuration.putProperty(Constants.EXTERNAL_TEMPLATE_PROPERTY_KEY,
                    schemaCompiler.getCompilerProperties().getProperty(
                            SchemaConstants.SchemaPropertyNames.BEAN_WRITER_TEMPLATE_KEY));

        }

        //process the unwrapped parameters
        if (!configuration.isParametersWrapped()) {
            //figure out the unwrapped operations
            AxisService axisService = configuration.getAxisService();

            for (Iterator operations = axisService.getOperations();
                 operations.hasNext();) {
                AxisOperation op = (AxisOperation) operations.next();
                if (WSDLUtil.isInputPresentForMEP(op.getMessageExchangePattern())) {
                    walkSchema(op.getMessage(
                            WSDLConstants.MESSAGE_LABEL_IN_VALUE),
                            mapper,
                            schemaMap,
                            op.getName().getLocalPart());
                }


            }
        }

        //set the type mapper to the config
        configuration.setTypeMapper(mapper);

    }

    /**
     * Populate the schema objects into the
     *
     * @param schemaMap
     * @param schemaList
     */
    private static void populateSchemaMap(Map schemaMap, List schemaList) {
        for (int i = 0; i < schemaList.size(); i++) {
            XmlSchema xmlSchema = (XmlSchema) schemaList.get(i);
            schemaMap.put(xmlSchema.getTargetNamespace(), xmlSchema);
        }
    }

    /**
     * @param message
     * @param mapper
     */
    private static void walkSchema(AxisMessage message,
                                   TypeMapper mapper,
                                   Map schemaMap,
                                   String opName) {

        if (message.getParameter(Constants.UNWRAPPED_KEY) != null) {
            XmlSchemaType schemaType = message.getSchemaElement().getSchemaType();
            //create a type mapper
            processXMLSchemaComplexType(schemaType, mapper, opName, schemaMap);
        }
    }

    private static void processXMLSchemaComplexType(XmlSchemaType schemaType, TypeMapper mapper, String opName, Map schemaMap) {
        if (schemaType instanceof XmlSchemaComplexType) {
            XmlSchemaComplexType cmplxType = (XmlSchemaComplexType) schemaType;
            if (cmplxType.getContentModel() == null) {
                processSchemaSequence(cmplxType.getParticle(), mapper, opName, schemaMap);
            } else {
                processComplexContentModel(cmplxType, mapper, opName, schemaMap);
            }
        }
    }

    private static void processComplexContentModel(XmlSchemaComplexType cmplxType, TypeMapper mapper, String opName, Map schemaMap) {
        XmlSchemaContentModel contentModel = cmplxType.getContentModel();
        if (contentModel instanceof XmlSchemaComplexContent) {
            XmlSchemaComplexContent xmlSchemaComplexContent = (XmlSchemaComplexContent) contentModel;
            XmlSchemaContent content = xmlSchemaComplexContent.getContent();
            if (content instanceof XmlSchemaComplexContentExtension) {
                XmlSchemaComplexContentExtension schemaExtension = (XmlSchemaComplexContentExtension) content;

                // process particles inside this extension, if any
                processSchemaSequence(schemaExtension.getParticle(), mapper, opName, schemaMap);

                // now we need to get the schema of the extension type from the parent schema. For that let's first retrieve
                // the parent schema
                XmlSchema parentSchema = (XmlSchema) schemaMap.get(schemaExtension.getBaseTypeName().getNamespaceURI());

                // ok now we got the parent schema. Now let's get the extension's schema type

                XmlSchemaType extensionSchemaType = parentSchema.getTypeByName(schemaExtension.getBaseTypeName());

                processXMLSchemaComplexType(extensionSchemaType, mapper, opName, schemaMap);
            }
        }
    }

    private static void processSchemaSequence(XmlSchemaParticle particle, TypeMapper mapper, String opName, Map schemaMap) {
        if (particle instanceof XmlSchemaSequence) {
            XmlSchemaObjectCollection items =
                    ((XmlSchemaSequence) particle).getItems();
            for (Iterator i = items.getIterator(); i.hasNext();) {
                Object item = i.next();
                // get each and every element in the sequence and
                // traverse through them
                if (item instanceof XmlSchemaElement) {
                    //populate the map with the partname - class name
                    //attached to the schema element
                    XmlSchemaElement xmlSchemaElement = (XmlSchemaElement) item;
                    XmlSchemaType eltSchemaType = xmlSchemaElement.getSchemaType();
                    if (eltSchemaType != null) {
                        //there is a schema type object.We can utilize that
                        populateClassName(eltSchemaType, mapper, opName, xmlSchemaElement);
                    } else if (xmlSchemaElement.getSchemaTypeName() != null) {
                        //there is no schema type object but there is a
                        //schema type QName.  Use that Qname to look up the
                        //schematype in other schema objects
                        eltSchemaType = findSchemaType(schemaMap,
                                xmlSchemaElement.getSchemaTypeName());
                        if (eltSchemaType != null) {
                            populateClassName(eltSchemaType, mapper, opName, xmlSchemaElement);
                        } else if (xmlSchemaElement.getSchemaTypeName().equals(SchemaConstants.XSD_ANYTYPE)) {
                            QName partQName = WSDLUtil.getPartQName(opName,
                                    WSDLConstants.INPUT_PART_QNAME_SUFFIX,
                                    xmlSchemaElement.getName());

                            if (xmlSchemaElement.getMaxOccurs() > 1) {
                                mapper.addTypeMappingName(partQName, "org.apache.axiom.om.OMElement[]");
                            } else {
                                mapper.addTypeMappingName(partQName, "org.apache.axiom.om.OMElement");
                            }
                        }
                    }
                } else if (item instanceof XmlSchemaAny) {

                    // if this is an instance of xs:any, then there is no part name for it. Using ANY_ELEMENT_FIELD_NAME
                    // for it for now

                    //we have to handle both maxoccurs 1 and maxoccurs > 1 situation
                    XmlSchemaAny xmlSchemaAny = (XmlSchemaAny) item;

                    QName partQName = WSDLUtil.getPartQName(opName,
                            WSDLConstants.INPUT_PART_QNAME_SUFFIX,
                            Constants.ANY_ELEMENT_FIELD_NAME);

                    if (((XmlSchemaAny) item).getMaxOccurs() > 1) {
                        mapper.addTypeMappingName(partQName, "org.apache.axiom.om.OMElement[]");
                    } else {
                        mapper.addTypeMappingName(partQName, "org.apache.axiom.om.OMElement");
                    }

                }

            }

        }
    }

    // private static void

    /**
     * Util method to populate the class name into the typeMap
     *
     * @param eltSchemaType
     */
    private static void populateClassName(XmlSchemaType eltSchemaType,
                                          TypeMapper typeMap,
                                          String opName,
                                          XmlSchemaElement xmlSchemaElement) {

        boolean isArray = xmlSchemaElement.getMaxOccurs() > 1;

        Map metaInfoMap = eltSchemaType.getMetaInfoMap();

        if (metaInfoMap != null) {
            String className = (String) metaInfoMap.
                    get(SchemaConstants.SchemaCompilerInfoHolder.CLASSNAME_KEY);

            // this is a temporary patch
            // the acual problem is keeping the class name details on the schemaType in
            // XmlSchema compiler.
            // we have to store them in XmlElement
            if (isArray && !className.endsWith("[]")) {
                className += "[]";
            } else if (!isArray && className.endsWith("[]")) {
                className = className.substring(0, className.length() - 2);
            }


            QName partQName = WSDLUtil.getPartQName(opName,
                    WSDLConstants.INPUT_PART_QNAME_SUFFIX,
                    xmlSchemaElement.getName());
            typeMap.addTypeMappingName(partQName, className);
            if (Boolean.TRUE.equals(
                    metaInfoMap.get(SchemaConstants.
                            SchemaCompilerInfoHolder.CLASSNAME_PRIMITVE_KEY))) {

                //this type is primitive - add that to the type mapper status
                //for now lets add a boolean
                typeMap.addTypeMappingStatus(partQName, Boolean.TRUE);
            }
        }
    }


    /**
     * Look for a given schema type given the schema type Qname
     *
     * @param schemaMap
     * @return null if the schema is not found
     */
    private static XmlSchemaType findSchemaType(Map schemaMap, QName schemaTypeName) {
        //find the schema
        XmlSchema schema = (XmlSchema) schemaMap.get(schemaTypeName.getNamespaceURI());
        if (schema != null) {
            return schema.getTypeByName(schemaTypeName);
        }
        return null;
    }

    /**
     * populate parameters from the user
     *
     * @param options
     */
    private static void populateUserparameters(CompilerOptions options, CodeGenConfiguration configuration) {
        Map propertyMap = configuration.getProperties();
        if (propertyMap.containsKey(SchemaConstants.SchemaCompilerArguments.WRAP_SCHEMA_CLASSES)) {
            if (Boolean.valueOf(
                    propertyMap.get(SchemaConstants.SchemaCompilerArguments.WRAP_SCHEMA_CLASSES).toString()).
                    booleanValue()) {
                options.setWrapClasses(true);
            } else {
                options.setWrapClasses(false);
            }
        }

        if (propertyMap.containsKey(SchemaConstants.SchemaCompilerArguments.WRITE_SCHEMA_CLASSES)) {
            if (Boolean.valueOf(
                    propertyMap.get(SchemaConstants.SchemaCompilerArguments.WRITE_SCHEMA_CLASSES).toString()).
                    booleanValue()) {
                options.setWriteOutput(true);
            } else {
                options.setWriteOutput(false);
            }
        }

        // add the custom package name
        if (propertyMap.containsKey(SchemaConstants.SchemaCompilerArguments.PACKAGE)) {
            String packageName = (String) propertyMap.get(SchemaConstants.SchemaCompilerArguments.PACKAGE);
            if (packageName != null || !"".equals(packageName)) {
                options.setPackageName(packageName);
            }

        }

        //add custom mapper package name
        if (propertyMap.containsKey(SchemaConstants.SchemaCompilerArguments.MAPPER_PACKAGE)) {
            String packageName = (String) propertyMap.get(SchemaConstants.SchemaCompilerArguments.MAPPER_PACKAGE);
            if (packageName != null || !"".equals(packageName)) {
                options.setMapperClassPackage(packageName);
            }

        }

        //set helper mode
        //this becomes effective only if the classes are unpacked
        if (!options.isWrapClasses()) {
            if (propertyMap.containsKey(SchemaConstants.SchemaCompilerArguments.HELPER_MODE)) {
                options.setHelperMode(true);
            }
        }
    }


    /**
     * populate the default options - called before the applying of user parameters
     *
     * @param options
     */
    private static void populateDefaultOptions(CompilerOptions options,
                                               CodeGenConfiguration configuration) {
        //create the output directory
        File outputDir = configuration.isFlattenFiles() ?
                configuration.getOutputLocation() :
                new File(configuration.getOutputLocation(), configuration.getSourceLocation());

        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        /// these options need to be taken from the command line
        options.setOutputLocation(outputDir);
        options.setNs2PackageMap(configuration.getUri2PackageNameMap() == null ?
                new HashMap() :
                configuration.getUri2PackageNameMap());

        //default setting is to set the wrap status depending on whether it's
        //the server side or the client side
        if (configuration.isServerSide()) {
            //for the serverside we generate unwrapped  by default
            options.setWrapClasses(false);
            //for the serverside we write the output by default
            options.setWriteOutput(true);
        } else {
            // for the client let the users preference be the word here
            options.setWrapClasses(configuration.isPackClasses());
            //for the client side the default setting is not to write the
            //output
            options.setWriteOutput(!configuration.isPackClasses());
        }

        if (configuration.isGenerateAll()) {
            options.setGenerateAll(true);
        }

        if (configuration.isBackwordCompatibilityMode()) {
            options.setBackwordCompatibilityMode(true);
        }

        if (configuration.isSuppressPrefixesMode()) {
            options.setSuppressPrefixesMode(true);
        }
    }

}
