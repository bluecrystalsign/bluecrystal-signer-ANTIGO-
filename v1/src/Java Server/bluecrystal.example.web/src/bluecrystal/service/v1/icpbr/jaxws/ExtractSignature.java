
package bluecrystal.service.v1.icpbr.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "extractSignature", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "extractSignature", namespace = "http://icpbr.v1.service.bluecrystal/")
public class ExtractSignature {

    @XmlElement(name = "sign", namespace = "")
    private String sign;

    /**
     * 
     * @return
     *     returns String
     */
    public String getSign() {
        return this.sign;
    }

    /**
     * 
     * @param sign
     *     the value for the sign property
     */
    public void setSign(String sign) {
        this.sign = sign;
    }

}
