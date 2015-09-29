package bluecrystal.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.ws.soap.SOAPFaultException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MessageHandler implements SOAPHandler<SOAPMessageContext> {
	static final Logger LOG = LoggerFactory.getLogger(MessageHandler.class);
	
	@Override
	public boolean handleMessage(SOAPMessageContext context) {

//		System.out.println("Server : handleMessage()......");

		Boolean isRequest = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

		// for response message only, true for outbound messages, false for
		// inbound
		if (!isRequest) {

			try {
				SOAPMessage soapMsg = context.getMessage();
//				SOAPEnvelope soapEnv = soapMsg.getSOAPPart().getEnvelope();
//				SOAPHeader soapHeader = soapEnv.getHeader();

				// if no header, add one
//				if (soapHeader == null) {
//					soapHeader = soapEnv.addHeader();
//					// throw exception
//					generateSOAPErrMessage(soapMsg, "No SOAP header.");
//				}

				// Get client mac address from SOAP header
//				Iterator it = soapHeader
//						.extractHeaderElements(SOAPConstants.URI_SOAP_ACTOR_NEXT);

				// if no header block for next actor found? throw exception
//				if (it == null || !it.hasNext()) {
//					generateSOAPErrMessage(soapMsg,
//							"No header block for next actor.");
//				}

				// tracking
//				System.out.println();
//				soapMsg.writeTo(System.out);
//				String s = soapMsg.toString();
//				System.out.println();
				
				OutputStream os = new ByteArrayOutputStream();
				soapMsg.writeTo(os);
				LOG.info(os.toString());

			} catch (SOAPException e) {
				System.err.println(e);
			} catch (IOException e) {
				System.err.println(e);
			}

		}

		// continue other handler chain
		return true;
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {

//		System.out.println("Server : handleFault()......");

		return true;
	}

	@Override
	public void close(MessageContext context) {
//		System.out.println("Server : close()......");
	}

	@Override
	public Set<QName> getHeaders() {
//		System.out.println("Server : getHeaders()......");
		return null;
	}

	private void generateSOAPErrMessage(SOAPMessage msg, String reason) {
		try {
			SOAPBody soapBody = msg.getSOAPPart().getEnvelope().getBody();
			SOAPFault soapFault = soapBody.addFault();
			soapFault.setFaultString(reason);
			throw new SOAPFaultException(soapFault);
		} catch (SOAPException e) {
		}
	}
}
