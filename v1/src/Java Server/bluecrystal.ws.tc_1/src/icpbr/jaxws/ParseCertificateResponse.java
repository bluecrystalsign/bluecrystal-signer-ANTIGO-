
package bluecrystal.service.v1.icpbr.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "parseCertificateResponse", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "parseCertificateResponse", namespace = "http://icpbr.v1.service.bluecrystal/")
public class ParseCertificateResponse {

    @XmlElement(name = "return", namespace = "", nillable = true)
    private bluecrystal.domain.NameValue[] _return;

    /**
     * 
     * @return
     *     returns NameValue[]
     */
    public bluecrystal.domain.NameValue[] getReturn() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void setReturn(bluecrystal.domain.NameValue[] _return) {
        this._return = _return;
    }

}
