
package bluecrystal.service.v1.icpbr.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "extractSignCompareResponse", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "extractSignCompareResponse", namespace = "http://icpbr.v1.service.bluecrystal/")
public class ExtractSignCompareResponse {

    @XmlElement(name = "return", namespace = "")
    private bluecrystal.domain.SignCompare _return;

    /**
     * 
     * @return
     *     returns SignCompare
     */
    public bluecrystal.domain.SignCompare getReturn() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void setReturn(bluecrystal.domain.SignCompare _return) {
        this._return = _return;
    }

}
