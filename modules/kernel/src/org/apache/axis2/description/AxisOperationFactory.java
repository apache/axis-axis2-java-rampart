package org.apache.axis2.description;

import org.apache.axis2.AxisFault;
import org.apache.axis2.i18n.Messages;
import org.apache.axis2.wsdl.WSDLConstants;

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
*
*
*/

public class AxisOperationFactory implements WSDLConstants {

    public static AxisOperation getAxisOperation(int mepURI) throws AxisFault {
        AxisOperation abOpdesc;

        switch (mepURI) {
            case WSDL20_2004Constants.MEP_CONSTANT_IN_ONLY : {
                abOpdesc = new InOnlyAxisOperation();
                abOpdesc.setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_IN_ONLY);
                break;
            }
            case WSDL20_2004Constants.MEP_CONSTANT_OUT_ONLY : {
                abOpdesc = new OutOnlyAxisOperation();
                abOpdesc.setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_OUT_ONLY);
                break;
            }
            case WSDL20_2004Constants.MEP_CONSTANT_IN_OUT : {
                abOpdesc = new InOutAxisOperation();
                abOpdesc.setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_IN_OUT);
                break;
            }
            case WSDL20_2004Constants.MEP_CONSTANT_IN_OPTIONAL_OUT : {
                abOpdesc = new InOutAxisOperation();
                abOpdesc.setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_IN_OPTIONAL_OUT);
                break;
            }
            case WSDL20_2004Constants.MEP_CONSTANT_ROBUST_IN_ONLY : {
                abOpdesc = new InOutAxisOperation();
                abOpdesc.setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_ROBUST_IN_ONLY);
                break;
            }
            case WSDL20_2004Constants.MEP_CONSTANT_OUT_IN : {
                abOpdesc = new OutInAxisOperation();
                abOpdesc.setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_OUT_IN);
                break;
            }
            case WSDL20_2004Constants.MEP_CONSTANT_OUT_OPTIONAL_IN : {
                abOpdesc = new OutInAxisOperation();
                abOpdesc.setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_OUT_OPTIONAL_IN);
                break;
            }
            case WSDL20_2004Constants.MEP_CONSTANT_ROBUST_OUT_ONLY : {
                abOpdesc = new RobustOutOnlyAxisOperation();
                abOpdesc.setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_ROBUST_OUT_ONLY);
                break;
            }
            default : {
                throw new AxisFault(Messages.getMessage("unSupportedMEP", "ID is " + mepURI));
            }
        }
        return abOpdesc;
    }

    //FIXME add in the latest MEP URIs
    public static AxisOperation getOperationDescription(String mepURI) throws AxisFault {
        AxisOperation abOpdesc;
        if (WSDL20_2004Constants.MEP_URI_IN_ONLY.equals(mepURI) || WSDL20_2006Constants.MEP_URI_IN_ONLY.equals(mepURI)) {
            abOpdesc = new InOnlyAxisOperation();
        } else if (WSDL20_2004Constants.MEP_URI_OUT_ONLY.equals(mepURI) || WSDL20_2006Constants.MEP_URI_OUT_ONLY.equals(mepURI)) {
            abOpdesc = new OutOnlyAxisOperation();
        } else if (WSDL20_2004Constants.MEP_URI_IN_OUT.equals(mepURI) || WSDL20_2004Constants.MEP_URI_IN_OUT_03.equals(mepURI) || WSDL20_2006Constants.MEP_URI_IN_OUT.equals(mepURI)) {
            abOpdesc = new InOutAxisOperation();
        } else if (WSDL20_2004Constants.MEP_URI_IN_OPTIONAL_OUT.equals(mepURI) || WSDL20_2006Constants.MEP_URI_IN_OPTIONAL_OUT.equals(mepURI)) {
            abOpdesc = new InOutAxisOperation();
        } else if (WSDL20_2004Constants.MEP_URI_OUT_IN.equals(mepURI) || WSDL20_2006Constants.MEP_URI_OUT_IN.equals(mepURI)) {
            abOpdesc = new OutInAxisOperation();
        } else if (WSDL20_2004Constants.MEP_URI_OUT_OPTIONAL_IN.equals(mepURI) || WSDL20_2006Constants.MEP_URI_OUT_OPTIONAL_IN.equals(mepURI)) {
            abOpdesc = new OutInAxisOperation();
        } else if (WSDL20_2004Constants.MEP_URI_ROBUST_OUT_ONLY.equals(mepURI) || WSDL20_2006Constants.MEP_URI_ROBUST_OUT_ONLY.equals(mepURI)) {
            abOpdesc = new OutInAxisOperation();
        } else if (WSDL20_2004Constants.MEP_URI_ROBUST_IN_ONLY.equals(mepURI) || WSDL20_2006Constants.MEP_URI_ROBUST_IN_ONLY.equals(mepURI)) {
            abOpdesc = new InOnlyAxisOperation();
        }else {
            throw new AxisFault(Messages.getMessage("unSupportedMEP", "ID is " + mepURI));
        }
        abOpdesc.setMessageExchangePattern(mepURI);
        return abOpdesc;
    }
}
