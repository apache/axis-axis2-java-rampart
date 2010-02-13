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

package org.apache.axis2.jaxws.registry;

import java.util.Hashtable;
import java.util.Map;

import org.apache.axis2.jaxws.client.factory.DescriptorFactory;
import org.apache.axis2.jaxws.client.factory.ProxyHandlerFactory;
import org.apache.axis2.jaxws.message.databinding.impl.JAXBBlockFactoryImpl;
import org.apache.axis2.jaxws.message.databinding.impl.OMBlockFactoryImpl;
import org.apache.axis2.jaxws.message.databinding.impl.SOAPEnvelopeBlockFactoryImpl;
import org.apache.axis2.jaxws.message.databinding.impl.SourceBlockFactoryImpl;
import org.apache.axis2.jaxws.message.databinding.impl.XMLStringBlockFactoryImpl;
import org.apache.axis2.jaxws.message.factory.JAXBBlockFactory;
import org.apache.axis2.jaxws.message.factory.MessageFactory;
import org.apache.axis2.jaxws.message.factory.OMBlockFactory;
import org.apache.axis2.jaxws.message.factory.SAAJConverterFactory;
import org.apache.axis2.jaxws.message.factory.SOAPEnvelopeBlockFactory;
import org.apache.axis2.jaxws.message.factory.SourceBlockFactory;
import org.apache.axis2.jaxws.message.factory.XMLPartFactory;
import org.apache.axis2.jaxws.message.factory.XMLStringBlockFactory;
import org.apache.axis2.jaxws.message.impl.MessageFactoryImpl;
import org.apache.axis2.jaxws.message.impl.XMLPartFactoryImpl;
import org.apache.axis2.jaxws.message.util.impl.SAAJConverterFactoryImpl;

/**
 * FactoryRegistry
 * Registry containing Factories related to the JAX-WS Implementation
 */
public class FactoryRegistry {

	private final static Map<Class,Object> table;
	static {
		table = new Hashtable<Class,Object>();
		table.put(XMLStringBlockFactory.class, new XMLStringBlockFactoryImpl());
		table.put(JAXBBlockFactory.class, new JAXBBlockFactoryImpl());
		table.put(OMBlockFactory.class, new OMBlockFactoryImpl());
		table.put(SourceBlockFactory.class, new SourceBlockFactoryImpl());
		table.put(SOAPEnvelopeBlockFactory.class, new SOAPEnvelopeBlockFactoryImpl());
		table.put(MessageFactory.class, new MessageFactoryImpl());
		table.put(XMLPartFactory.class, new XMLPartFactoryImpl());
		table.put(SAAJConverterFactory.class, new SAAJConverterFactoryImpl());
		table.put(ProxyHandlerFactory.class, new ProxyHandlerFactory());
		table.put(DescriptorFactory.class, new DescriptorFactory());
	}
	/**
	 * FactoryRegistry is currently a static singleton
	 */
	private FactoryRegistry() {
	}
	
	/**
	 * getFactory
	 * @param intface of the Factory
	 * @return Object that is the factory implementation for the intface
	 */
	public static Object getFactory(Class intface) {
		return table.get(intface);
	}
}
