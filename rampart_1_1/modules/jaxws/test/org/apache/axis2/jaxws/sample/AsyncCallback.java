/**
 * 
 */
package org.apache.axis2.jaxws.sample;

import java.util.concurrent.ExecutionException;

import javax.xml.ws.AsyncHandler;
import javax.xml.ws.Response;

import org.test.sample.nonwrap.ReturnType;



/**
 * @author nvthaker
 *
 */
public class AsyncCallback implements AsyncHandler {

	/**
	 * 
	 */
	public AsyncCallback() {
		super();
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see javax.xml.ws.AsyncHandler#handleResponse(javax.xml.ws.Response)
	 */
	public void handleResponse(Response response) {
		try{
			Object obj = response.get();
			if(obj instanceof ReturnType){
				ReturnType type = (ReturnType)obj;
				System.out.println(">>Return String = "+type.getReturnStr());
				return;
			}
			
		}catch(ExecutionException e){
			e.printStackTrace();
		}catch(InterruptedException e){
			e.printStackTrace();
		}

	}

}
