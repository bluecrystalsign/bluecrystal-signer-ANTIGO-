
package bluecrystal.service.v1.icpbr.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "composeCoSignEnvelopeADRB21", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "composeCoSignEnvelopeADRB21", namespace = "http://icpbr.v1.service.bluecrystal/")
public class ComposeCoSignEnvelopeADRB21 {

    @XmlElement(name = "signatute", namespace = "", nillable = true)
    private bluecrystal.domain.Signature[] signatute;

    /**
     * 
     * @return
     *     returns Signature[]
     */
    public bluecrystal.domain.Signature[] getSignatute() {
        return this.signatute;
    }

    /**
     * 
     * @param signatute
     *     the value for the signatute property
     */
    public void setSignatute(bluecrystal.domain.Signature[] signatute) {
        this.signatute = signatute;
    }

}
