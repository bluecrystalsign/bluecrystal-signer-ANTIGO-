
package bluecrystal.service.v1.rebuilder;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the bluecrystal.service.v1.rebuilder package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _Exception_QNAME = new QName("http://rebuilder.v1.service.bluecrystal/", "Exception");
    private final static QName _RebuildEnvelope_QNAME = new QName("http://rebuilder.v1.service.bluecrystal/", "rebuildEnvelope");
    private final static QName _RebuildEnvelopeResponse_QNAME = new QName("http://rebuilder.v1.service.bluecrystal/", "rebuildEnvelopeResponse");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: bluecrystal.service.v1.rebuilder
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link Exception }
     * 
     */
    public Exception createException() {
        return new Exception();
    }

    /**
     * Create an instance of {@link RebuildEnvelope }
     * 
     */
    public RebuildEnvelope createRebuildEnvelope() {
        return new RebuildEnvelope();
    }

    /**
     * Create an instance of {@link RebuildEnvelopeResponse }
     * 
     */
    public RebuildEnvelopeResponse createRebuildEnvelopeResponse() {
        return new RebuildEnvelopeResponse();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Exception }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://rebuilder.v1.service.bluecrystal/", name = "Exception")
    public JAXBElement<Exception> createException(Exception value) {
        return new JAXBElement<Exception>(_Exception_QNAME, Exception.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RebuildEnvelope }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://rebuilder.v1.service.bluecrystal/", name = "rebuildEnvelope")
    public JAXBElement<RebuildEnvelope> createRebuildEnvelope(RebuildEnvelope value) {
        return new JAXBElement<RebuildEnvelope>(_RebuildEnvelope_QNAME, RebuildEnvelope.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RebuildEnvelopeResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://rebuilder.v1.service.bluecrystal/", name = "rebuildEnvelopeResponse")
    public JAXBElement<RebuildEnvelopeResponse> createRebuildEnvelopeResponse(RebuildEnvelopeResponse value) {
        return new JAXBElement<RebuildEnvelopeResponse>(_RebuildEnvelopeResponse_QNAME, RebuildEnvelopeResponse.class, null, value);
    }

}
