
package bluecrystal.service.v1.icpbr.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "validateSignatureByPolicy", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "validateSignatureByPolicy", namespace = "http://icpbr.v1.service.bluecrystal/", propOrder = {
    "signCmsb64",
    "psb64"
})
public class ValidateSignatureByPolicy {

    @XmlElement(name = "signCmsb64", namespace = "")
    private String signCmsb64;
    @XmlElement(name = "psb64", namespace = "")
    private String psb64;

    /**
     * 
     * @return
     *     returns String
     */
    public String getSignCmsb64() {
        return this.signCmsb64;
    }

    /**
     * 
     * @param signCmsb64
     *     the value for the signCmsb64 property
     */
    public void setSignCmsb64(String signCmsb64) {
        this.signCmsb64 = signCmsb64;
    }

    /**
     * 
     * @return
     *     returns String
     */
    public String getPsb64() {
        return this.psb64;
    }

    /**
     * 
     * @param psb64
     *     the value for the psb64 property
     */
    public void setPsb64(String psb64) {
        this.psb64 = psb64;
    }

}
