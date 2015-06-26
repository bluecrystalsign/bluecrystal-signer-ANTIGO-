
package bluecrystal.service.v1.icpbr.jaxws;

import java.util.Date;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "hashSignedAttribADRB10", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "hashSignedAttribADRB10", namespace = "http://icpbr.v1.service.bluecrystal/", propOrder = {
    "origHashb64",
    "signingTime",
    "x509"
})
public class HashSignedAttribADRB10 {

    @XmlElement(name = "origHashb64", namespace = "")
    private String origHashb64;
    @XmlElement(name = "signingTime", namespace = "")
    private Date signingTime;
    @XmlElement(name = "x509", namespace = "")
    private String x509;

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
    public String getX509() {
        return this.x509;
    }

    /**
     * 
     * @param x509
     *     the value for the x509 property
     */
    public void setX509(String x509) {
        this.x509 = x509;
    }

}
