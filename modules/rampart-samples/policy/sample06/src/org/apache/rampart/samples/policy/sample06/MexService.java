package org.apache.rampart.samples.policy.sample06;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.XMLStreamException;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axis2.AxisFault;
import org.apache.axis2.mex.MexConstants;
import org.apache.axis2.mex.om.Metadata;
import org.apache.axis2.mex.om.MetadataSection;

public class MexService {
    
    public OMElement get(OMElement element) throws AxisFault {
        
        MetadataSection section = new MetadataSection();
        section.setDialect(MexConstants.SPEC.DIALECT_TYPE_POLICY);
        section.setinlineData(getPolicy());
        
        List lst = new ArrayList();
        lst.add(section);
        
        Metadata mdata = new Metadata();
        mdata.setMetadatSections(lst);
        
        return mdata.toOM();
        
    }
    
    
    private OMElement getPolicy() throws AxisFault {
        
        try {
            
            File file = new File("sample06/mex_policy.xml");
            System.out.println(file.getAbsolutePath());
            StAXOMBuilder builder = new StAXOMBuilder(new FileInputStream(file));
            return builder.getDocumentElement();
        } catch (FileNotFoundException e) {
            throw new AxisFault("Error reading the file",e);
        } catch (XMLStreamException e) {
            throw new AxisFault("Error parsing the file",e);
        }
    }

}
