
package bluecrystal.service.v1.icpbr.jaxws;

import java.util.Date;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "hashSignedAttribADRB21", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "hashSignedAttribADRB21", namespace = "http://icpbr.v1.service.bluecrystal/", propOrder = {
    "origHashb64",
    "signingTime",
    "certb64"
})
public class HashSignedAttribADRB21 {

    @XmlElement(name = "origHashb64", namespace = "")
    private String origHashb64;
    @XmlElement(name = "signingTime", namespace = "")
    private Date signingTime;
    @XmlElement(name = "certb64", namespace = "")
    private String certb64;

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
