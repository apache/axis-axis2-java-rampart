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
package org.apache.axis2.jaxws.message.databinding.impl;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.jaxws.ExceptionFactory;
import org.apache.axis2.jaxws.i18n.Messages;
import org.apache.axis2.jaxws.message.MessageException;
import org.apache.axis2.jaxws.message.databinding.SourceBlock;
import org.apache.axis2.jaxws.message.factory.BlockFactory;
import org.apache.axis2.jaxws.message.impl.BlockImpl;
import org.apache.axis2.jaxws.message.util.DOMReader;
import org.apache.axis2.jaxws.message.util.Reader2Writer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.bind.util.JAXBSource;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;

/**
 * SourceBlock
 * 
 * Block containing a business object that is a javax.xml.transform.Source.
 * 
 * The javax.xml.transform.Source is an interface.  The actual concrete class
 * may be one of the following:
 * 	 - StreamSource
 * 	 - DOMSource
 *   - JAXBSource
 *   - SAXSource
 *   - StAXSource
 *   
 * During processing of the block, the block is free to change the representation
 * from one source to another.  (i.e. if you initially seed this with a SAXSource, 
 * but a later access may give you a StAXSource).
 * 
 * A Source is consumed when read.  The block will make a copy of the source
 * if a non-consumable request is made.
 */
public class SourceBlockImpl extends BlockImpl implements SourceBlock {

	private static XMLInputFactory inputFactory = XMLInputFactory.newInstance();
	private static XMLOutputFactory outputFactory = XMLOutputFactory.newInstance();
	
	private static Class staxSource = null;
	static {
		try {
			// Dynamically discover if StAXSource is available
			staxSource = Class.forName("javax.xml.transform.stax.StAXSource");
		} catch (Exception e) { }
	}
	
	/**
	 * Constructor called from factory
	 * @param busObject
	 * @param qName
	 * @param factory
	 */
	SourceBlockImpl(Source busObject, QName qName, BlockFactory factory) throws MessageException {
		super(busObject, null, qName, factory);

		// Check validity of Source
		if (busObject instanceof DOMSource ||
			busObject instanceof SAXSource ||
			busObject instanceof StreamSource ||
			(busObject.getClass().equals(staxSource)) ||
			busObject instanceof JAXBSource) {
			// Okay, these are supported Source objects
		} else {
			// TODO NLS
			throw ExceptionFactory.makeMessageException(Messages.getMessage("SourceNotSupported", busObject.getClass().getName()));
		}
	}
	

	/**
	 * Constructor called from factory
	 * @param reader
	 * @param qName
	 * @param factory
	 */
	public SourceBlockImpl(OMElement omElement, QName qName, BlockFactory factory) {
		super(omElement, null, qName, factory);
	}

	@Override
	protected Object _getBOFromReader(XMLStreamReader reader, Object busContext) throws XMLStreamException {
		
		// Best solution is to use a StAXSource
		if (staxSource != null) {
			try {
				// TODO Constructor should be statically cached for performance
				Constructor c = staxSource.getDeclaredConstructor(new Class[] {XMLStreamReader.class} );
				return c.newInstance(new Object[] {reader});
			} catch (Exception e) {
			}
		}
		
		// TODO StreamSource is not performant...work is needed here to make this faster
		Reader2Writer r2w = new Reader2Writer(reader);
		String text = r2w.getAsString();
		StringReader sr = new StringReader(text);
		return new StreamSource(sr);
		
	}

	@Override
	protected XMLStreamReader _getReaderFromBO(Object busObj, Object busContext) throws XMLStreamException  {
		// TODO not sure if this is always the most performant way to do this.
		if (busObj instanceof DOMSource) {
			// Let's use our own DOMReader for now...
			Element element = null;
			
			//TODO busObj can be any of the subclasses of Node -- Document, Elemeent, Entity, Text, ETC.
			//May need to add code to check for other supported Node type other than Document and Element.
			Node node = ((DOMSource)busObj).getNode();
			if(node instanceof Document){
				element = ((Document)node).getDocumentElement();
			}else{
				element = (Element) ((DOMSource)busObj).getNode();
			}
			
			// We had some problems with testers producing DOMSources w/o Namespaces.  
			// It's easy to catch this here.
			if (element.getLocalName() == null) {
				throw new XMLStreamException(ExceptionFactory.makeMessageException(Messages.getMessage("JAXBSourceNamespaceErr")));
			}
			
			return new DOMReader(element);
		} 
		
		if(busObj instanceof StreamSource){
			return inputFactory.createXMLStreamReader((Source) busObj);
		}
		//TODO: For GM we need to only use this approach when absolutely necessary.  
        // For example, we don't want to do this if this is a (1.6) StaxSource or if the installed parser provides 
        // a better solution.
		//TODO: Uncomment this code if woodstock parser handles JAXBSource and SAXSource correctly.
		//return inputFactory.createXMLStreamReader((Source) busObj);
		return _slow_getReaderFromSource((Source)busObj);
	}
	
	/**
     * Creates an XMLStreamReader from a Source using a slow but proven algorithm.
     */
   private XMLStreamReader _slow_getReaderFromSource(Source src) throws XMLStreamException {
	   try{
           ByteArrayOutputStream out = new ByteArrayOutputStream();
           Result result = new StreamResult(out);
           Transformer transformer =  TransformerFactory.newInstance().newTransformer();
           transformer.transform(src, result); 
	       ByteArrayInputStream bytes = new ByteArrayInputStream(out.toByteArray());
	       return inputFactory.createXMLStreamReader(bytes);
	   }catch(TransformerException e){
		   throw new XMLStreamException(e);
	   }
  
   }

	@Override
	protected void _outputFromBO(Object busObject, Object busContext, XMLStreamWriter writer) throws XMLStreamException {
		// There is no fast way to output the Source to a writer, so get the reader
		// and pass use the default reader->writer.
		XMLStreamReader reader = _getReaderFromBO(busObject, busContext);
		_outputFromReader(reader, writer);
	}


	@Override
	protected Object _getBOFromBO(Object busObject, Object busContext, boolean consume) {
		if (consume) {
			return busObject;
		} else {
			// TODO Missing Impl
			throw ExceptionFactory.makeMessageInternalException(Messages.getMessage("SourceMissingSupport", busObject.getClass().getName()), null);
		}
	}
	
	
}
