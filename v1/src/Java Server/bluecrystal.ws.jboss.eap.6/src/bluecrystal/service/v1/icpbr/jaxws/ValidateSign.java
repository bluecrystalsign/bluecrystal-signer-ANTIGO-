
package bluecrystal.service.v1.icpbr.jaxws;

import java.util.Date;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "validateSign", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "validateSign", namespace = "http://icpbr.v1.service.bluecrystal/", propOrder = {
    "signCmsb64",
    "origHashb64",
    "signingTime",
    "verifyCrlOcsp"
})
public class ValidateSign {

    @XmlElement(name = "signCmsb64", namespace = "")
    private String signCmsb64;
    @XmlElement(name = "origHashb64", namespace = "")
    private String origHashb64;
    @XmlElement(name = "signingTime", namespace = "")
    private Date signingTime;
    @XmlElement(name = "verifyCrlOcsp", namespace = "")
    private boolean verifyCrlOcsp;

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
    public String getOrigHashb64() {
        return this.origHashb64;
    }

    /**
     * 
     * @param origHashb64
     *     the value for the origHashb64 property
     */
    public void setOrigHashb64(String origHashb64) {
        this.origHashb64 = origHashb64;
    }

    /**
     * 
     * @return
     *     returns Date
     */
    public Date getSigningTime() {
        return this.signingTime;
    }

    /**
     * 
     * @param signingTime
     *     the value for the signingTime property
     */
    public void setSigningTime(Date signingTime) {
        this.signingTime = signingTime;
    }

    /**
     * 
     * @return
     *     returns boolean
     */
    public boolean isVerifyCrlOcsp() {
        return this.verifyCrlOcsp;
    }

    /**
     * 
     * @param verifyCrlOcsp
     *     the value for the verifyCrlOcsp property
     */
    public void setVerifyCrlOcsp(boolean verifyCrlOcsp) {
        this.verifyCrlOcsp = verifyCrlOcsp;
    }

}
