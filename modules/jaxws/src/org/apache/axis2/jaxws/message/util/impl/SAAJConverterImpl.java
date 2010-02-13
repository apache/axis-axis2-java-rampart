/*
 * Copyright 2004,2005 The Apache Software Foundation.
 * Copyright 2006 International Business Machines Corp.
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
package org.apache.axis2.jaxws.message.util.impl;

import java.lang.reflect.Method;
import java.util.Iterator;

import javax.xml.namespace.QName;
import javax.xml.soap.Detail;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.Name;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.soap.impl.builder.StAXSOAPModelBuilder;
import org.apache.axis2.jaxws.ExceptionFactory;
import org.apache.axis2.jaxws.i18n.Messages;
import org.apache.axis2.jaxws.message.MessageException;
import org.apache.axis2.jaxws.message.util.SAAJConverter;
import org.apache.axis2.jaxws.message.util.SOAPElementReader;

/**
 * SAAJConverterImpl
 * Provides an conversion methods between OM<->SAAJ
 */
public class SAAJConverterImpl implements SAAJConverter {

	private static final String SOAP11_ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/";
	private static final String SOAP12_ENV_NS = "http://www.w3.org/2003/05/soap-envelope";
	
	public static final String SOAP_1_1_PROTOCOL = "SOAP 1.1 Protocol"; 
	public static final String SOAP_1_2_PROTOCOL = "SOAP 1.2 Protocol";
	public static final String DYNAMIC_PROTOCOL  = "Dynamic Protocol"; 
	
	/**
	 * Constructed via SAAJConverterFactory
	 */
	SAAJConverterImpl() {
		super();
	}

	/* (non-Javadoc)
	 * @see org.apache.axis2.jaxws.message.util.SAAJConverter#toSAAJ(org.apache.axiom.soap.SOAPEnvelope)
	 */
	public SOAPEnvelope toSAAJ(org.apache.axiom.soap.SOAPEnvelope omEnvelope)
			throws MessageException {
		SOAPEnvelope soapEnvelope = null;
		try {
			// Build the default envelope
			OMNamespace ns = omEnvelope.getNamespace();
			MessageFactory mf = createMessageFactory(ns.getNamespaceURI());
			SOAPMessage sm = mf.createMessage();
			SOAPPart sp = sm.getSOAPPart();
			soapEnvelope = sp.getEnvelope();
			
			// The getSOAPEnvelope() call creates a default SOAPEnvelope with a SOAPHeader and SOAPBody.
			// The SOAPHeader and SOAPBody are removed (they will be added back in if they are present in the 
			// OMEnvelope).
			SOAPBody soapBody = soapEnvelope.getBody();
			if (soapBody != null) {
				soapBody.detachNode();
			}
			SOAPHeader soapHeader = soapEnvelope.getHeader();
			if (soapHeader != null) {
				soapHeader.detachNode();
			}
			
			// We don't know if there is a real OM tree or just a backing XMLStreamReader.
			// The best way to walk the data is to get the XMLStreamReader and use this 
			// to build the SOAPElements
			XMLStreamReader reader = omEnvelope.getXMLStreamReaderWithoutCaching();
			
			NameCreator nc = new NameCreator(soapEnvelope);
			buildSOAPTree(nc, soapEnvelope, null, reader, false);
		} catch (MessageException e) {
			throw e;
		} catch (SOAPException e) {
			throw ExceptionFactory.makeMessageException(e);
		}
		return soapEnvelope;
	}

	/* (non-Javadoc)
	 * @see org.apache.axis2.jaxws.message.util.SAAJConverter#toOM(javax.xml.soap.SOAPEnvelope)
	 */
	public org.apache.axiom.soap.SOAPEnvelope toOM(SOAPEnvelope saajEnvelope)
			throws MessageException {
		// Get a XMLStreamReader backed by a SOAPElement tree
		XMLStreamReader reader = new SOAPElementReader(saajEnvelope);
		// Get a SOAP OM Builder.  Passing null causes the version to be automatically triggered
		StAXSOAPModelBuilder builder = new StAXSOAPModelBuilder(reader, null);  
		// Create and return the OM Envelope
		org.apache.axiom.soap.SOAPEnvelope omEnvelope = builder.getSOAPEnvelope();
		return omEnvelope;
	}
	
	

	/* (non-Javadoc)
	 * @see org.apache.axis2.jaxws.message.util.SAAJConverter#toOM(javax.xml.soap.SOAPElement)
	 */
	public OMElement toOM(SOAPElement soapElement) throws MessageException {
		// Get a XMLStreamReader backed by a SOAPElement tree
		XMLStreamReader reader = new SOAPElementReader(soapElement);
		// Get a OM Builder.  Passing null causes the version to be automatically triggered
		StAXOMBuilder builder = new StAXOMBuilder(reader);  
		// Create and return the OM Envelope
		OMElement om = builder.getDocumentElement();
		return om;
	}

	/* (non-Javadoc)
	 * @see org.apache.axis2.jaxws.message.util.SAAJConverter#toSAAJ(org.apache.axiom.om.OMElement, javax.xml.soap.SOAPElement)
	 */
	public SOAPElement toSAAJ(OMElement omElement, SOAPElement parent) throws MessageException {
		XMLStreamReader reader = null;
		
		// If the OM element is not attached to a parser (builder), then the OM
		// is built and you cannot ask for XMLStreamReaderWithoutCaching.
		// This is probably a bug in OM.  You should be able to ask the OM whether
		// caching is supported.
		if (omElement.getBuilder() == null) {
			reader = omElement.getXMLStreamReader();
		} else {
			reader = omElement.getXMLStreamReaderWithoutCaching();
		}
		SOAPElement env = parent;
		while (env != null && !(env instanceof SOAPEnvelope)) {
			env = env.getParentElement();
		}
		if (env == null) {
			throw ExceptionFactory.makeMessageException(Messages.getMessage("SAAJConverterErr1"));
		}
		NameCreator nc = new NameCreator((SOAPEnvelope) env);
		return buildSOAPTree(nc, null, parent, reader, false);
	}
	

	/* (non-Javadoc)
	 * @see org.apache.axis2.jaxws.message.util.SAAJConverter#toSAAJ(org.apache.axiom.om.OMElement, javax.xml.soap.SOAPElement, javax.xml.soap.SOAPFactory)
	 */
	public SOAPElement toSAAJ(OMElement omElement, SOAPElement parent, SOAPFactory sf) throws MessageException {
		XMLStreamReader reader = null;
		
		// If the OM element is not attached to a parser (builder), then the OM
		// is built and you cannot ask for XMLStreamReaderWithoutCaching.
		// This is probably a bug in OM.  You should be able to ask the OM whether
		// caching is supported.
		if (omElement.getBuilder() == null) {
			reader = omElement.getXMLStreamReader();
		} else {
			reader = omElement.getXMLStreamReaderWithoutCaching();
		}
		NameCreator nc = new NameCreator(sf);
		return buildSOAPTree(nc, null, parent, reader, false);
	}

	/**
	 * Create MessageFactory using information from the envelope namespace 
	 * @param namespace
	 * @return
	 */
	public MessageFactory createMessageFactory(String namespace) throws MessageException, SOAPException {
		Method m = getNewInstanceProtocolMethod();
		MessageFactory mf = null;
		if (m == null) {
			if (namespace.equals(SOAP11_ENV_NS)) {
				mf = MessageFactory.newInstance();
			} else {
				throw ExceptionFactory.makeMessageException(Messages.getMessage("SOAP12WithSAAJ12Err"));
			}
		} else {
			String protocol = DYNAMIC_PROTOCOL;
			if (namespace.equals(SOAP11_ENV_NS)) {
				protocol = SOAP_1_1_PROTOCOL;
			} else if (namespace.equals(SOAP12_ENV_NS)) {
				protocol = SOAP_1_2_PROTOCOL;
			} 
			try {
				mf = (MessageFactory) m.invoke(null, new Object[] {protocol});
			} catch (Exception e) {
				throw ExceptionFactory.makeMessageException(e);
			}
		}
		return mf;
	}
	
	private Method newInstanceProtocolMethod = null;
	private Method getNewInstanceProtocolMethod() {
		if (newInstanceProtocolMethod == null) {
			try {
				newInstanceProtocolMethod = MessageFactory.class.getMethod("newInstance", new Class[] {String.class});
			} catch (Exception e) {
				// TODO Might want to log this.
				// Flow to here indicates that the installed SAAJ model does not support version 1.3
				newInstanceProtocolMethod = null;
			}
		}
		return newInstanceProtocolMethod;
	}
	
	/**
	 * Build SOAPTree
	 * Either the root or the parent is null.
	 * If the root is null, a new element is created under the parent using information from the reader
	 * If the parent is null, the existing root is updated with the information from the reader
	 * @param nc NameCreator
	 * @param root SOAPElement (the element that represents the data in the reader)
	 * @param parent (the parent of the element represented by the reader)
	 * @param reader XMLStreamReader. the first START_ELEMENT matches the root
	 * @param quitAtBody - true if quit reading after the body START_ELEMENT
	 */
	protected SOAPElement buildSOAPTree(NameCreator nc, 
					SOAPElement root, 
					SOAPElement parent, 
					XMLStreamReader reader, 
					boolean quitAtBody) 
		throws MessageException {
		try {
			while(reader.hasNext()) {
				int eventID = reader.next();	
				switch (eventID) {
				case XMLStreamReader.START_ELEMENT: {
					
					// The first START_ELEMENT defines the prefix and attributes of the root
					if (parent == null) {
						updateTagData(nc, root, reader);
						parent = root;
					} else {
						parent = createElementFromTag(nc, parent, reader);
						if (root == null) {
							root = parent;
						}
					}
					if (quitAtBody && parent instanceof SOAPBody) {
						return root;
					}
					break;
				}
				case XMLStreamReader.ATTRIBUTE: {
					String eventName ="ATTRIBUTE";
					this._unexpectedEvent(eventName);
				}
				case XMLStreamReader.NAMESPACE: {
					String eventName ="NAMESPACE";
					this._unexpectedEvent(eventName);
				}
				case XMLStreamReader.END_ELEMENT: {
					if (parent instanceof SOAPEnvelope) {
						parent = null;
					} else {
						parent = parent.getParentElement();
					}
					break;
				}
				case XMLStreamReader.CHARACTERS: {
					parent.addTextNode(reader.getText());
					break;
				}
				case XMLStreamReader.CDATA: {
					parent.addTextNode(reader.getText());
					break;
				}
				case XMLStreamReader.COMMENT: {
					// SOAP really doesn't have an adequate representation for comments.
					// The defacto standard is to add the whole element as a text node.
					parent.addTextNode("<!--" + reader.getText() + "-->");
					break;
				}
				case XMLStreamReader.SPACE: {
					parent.addTextNode(reader.getText());
					break;
				}
				case XMLStreamReader.START_DOCUMENT: {
					// Ignore
					break;
				}
				case XMLStreamReader.END_DOCUMENT: {
					// Ignore
					break;
				}
				case XMLStreamReader.PROCESSING_INSTRUCTION: {
					// Ignore 
					break;
				}
				case XMLStreamReader.ENTITY_REFERENCE: {
					// Ignore. this is unexpected in a web service message
					break;
				}
				case XMLStreamReader.DTD: {
					// Ignore. this is unexpected in a web service message
					break;
				}
				default:
					this._unexpectedEvent("EventID " +String.valueOf(eventID));
				}
			}	
		} catch (MessageException e) {
			throw e;
		} catch (XMLStreamException e) {
			throw ExceptionFactory.makeMessageException(e);
		} catch (SOAPException e) {
			throw ExceptionFactory.makeMessageException(e);
		}
		return root;
	}
	
	/**
	 * Create SOAPElement from the current tag data
	 * @param nc NameCreator
	 * @param parent SOAPElement for the new SOAPElement
	 * @param reader XMLStreamReader whose cursor is at the START_ELEMENT
	 * @return
	 */
	protected SOAPElement createElementFromTag(NameCreator nc, 
					SOAPElement parent, 
					XMLStreamReader reader) 
		throws SOAPException {
		// Unfortunately, the SAAJ object is a product of both the 
		// QName of the element and the parent object.  For example, 
		// All element children of a SOAPBody must be object's that are SOAPBodyElements.
		// createElement creates the proper child element.
		QName qName = reader.getName();
		String prefix = reader.getPrefix();
		Name name = nc.createName(qName.getLocalPart(), prefix, qName.getNamespaceURI());
		SOAPElement child = createElement(parent, name);
		
		// Update the tag data on the child
		updateTagData(nc, child, reader);
		return child;
	}
	
	/**
	 * Create child SOAPElement 
	 * @param parent SOAPElement
	 * @param name Name
	 * @return
	 */
	protected SOAPElement createElement(SOAPElement parent, Name name) 
		throws SOAPException {
		SOAPElement child;
		if (parent instanceof SOAPEnvelope) {
			if (name.getURI().equals(parent.getNamespaceURI())) {
				if (name.getLocalName().equals("Body")) {
					child = ((SOAPEnvelope)parent).addBody();
				} else {
					child = ((SOAPEnvelope)parent).addHeader();
				}
			} else {
				child = parent.addChildElement(name);
			}
		} else if (parent instanceof SOAPBody) {
			if (name.getURI().equals(parent.getNamespaceURI()) &&
			    name.getLocalName().equals("Fault")) {
				child = ((SOAPBody)parent).addFault();
			} else {
				child = ((SOAPBody)parent).addBodyElement(name);
			}
		} else if (parent instanceof SOAPHeader) {
			child = ((SOAPHeader)parent).addHeaderElement(name);
		} else if (parent instanceof SOAPFault) {
			// This call assumes that the addChildElement implementation
			// is smart enough to add "Detail" or "SOAPFaultElement" objects.
			child = parent.addChildElement(name);
		} else if (parent instanceof Detail) {
			child = ((Detail) parent).addDetailEntry(name); 
		} else {
			child = parent.addChildElement(name);
		}
	
		return child;
	}
	
	/**
	 * update the tag data of the SOAPElement
	 * @param NameCreator nc
	 * @param element SOAPElement
	 * @param reader XMLStreamReader whose cursor is at START_ELEMENT
	 */
	protected void updateTagData(NameCreator nc, 
			SOAPElement element, 
			XMLStreamReader reader) throws SOAPException {
		String prefix = reader.getPrefix();
		prefix = (prefix == null) ? "" : prefix;
		
		// Make sure the prefix is correct
		if (prefix.length() > 0 && !element.getPrefix().equals(prefix)) {
			element.setPrefix(prefix);
		}
		
		//Remove all of the namespace declarations on the element
		Iterator it = element.getNamespacePrefixes();
		while (it.hasNext()) {
			String aPrefix = (String)it.next();
			element.removeNamespaceDeclaration(aPrefix);
		}
		
		// Add the namespace declarations from the reader
		int size = reader.getNamespaceCount();
		for (int i=0; i<size; i++) {
			element.addNamespaceDeclaration(reader.getNamespacePrefix(i), reader.getNamespaceURI(i));
		}
		
		// Add attributes 
		addAttributes(nc, element, reader);
		
		return;
	}
	
	/** add attributes
	 * @param NameCreator nc
	 * @param element SOAPElement which is the target of the new attributes
	 * @param reader XMLStreamReader whose cursor is at START_ELEMENT
	 * @throws SOAPException
	 */
	protected void addAttributes(NameCreator nc, 
			SOAPElement element, 
			XMLStreamReader reader) throws SOAPException {
		
		// Add the attributes from the reader
		int size = reader.getAttributeCount();
		for (int i=0; i<size; i++) {
			QName qName = reader.getAttributeName(i);
			String prefix = reader.getAttributePrefix(i);
			String value = reader.getAttributeValue(i);
			Name name = nc.createName(qName.getLocalPart(), prefix, qName.getNamespaceURI());
			element.addAttribute(name, value);
		}
	}
	
	private void _unexpectedEvent(String event) throws MessageException {
		// Review We need NLS for this message, but this code will probably 
		// be added to JAX-WS.  So for now we there is no NLS.
		// TODO NLS
		throw ExceptionFactory.makeMessageException(Messages.getMessage("SAAJConverterErr2", event));
	}
	
	/**
	 * A Name can be created from either a SOAPEnvelope or SOAPFactory.
	 * Either one or the other is available when the converter is called. 
	 * NameCreator provides a level of abstraction which simplifies the code.
	 */
	protected class NameCreator {
		private SOAPEnvelope env = null;
		private SOAPFactory sf = null;
		
		public NameCreator(SOAPEnvelope env) {
			this.env = env;
		}
		
		public NameCreator(SOAPFactory sf) {
			this.sf = sf;
		}
		
		/**
		 * Creates a Name
		 * @param localName
		 * @param prefix
		 * @param uri
		 * @return Name
		 */
		public Name createName(String localName, String prefix, String uri)
			throws SOAPException{
			if (sf != null) {
				return sf.createName(localName, prefix, uri);
			} else {
				return env.createName(localName, prefix, uri);
			}
		}
		
	}
}
