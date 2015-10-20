
package bluecrystal.service.v1.icpbr.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "getCertSubject", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getCertSubject", namespace = "http://icpbr.v1.service.bluecrystal/")
public class GetCertSubject {

    @XmlElement(name = "certb64", namespace = "")
    private String certb64;

    /**
     * 
     * @return
     *     returns String
     */
    public String getCertb64() {
        return this.certb64;
    }

    /**
     * 
     * @param certb64
     *     the value for the certb64 property
     */
    public void setCertb64(String certb64) {
        this.certb64 = certb64;
    }

}
