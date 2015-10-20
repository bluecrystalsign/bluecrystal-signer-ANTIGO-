
package bluecrystal.service.v1.icpbr.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "rebuildEnvelope", namespace = "http://icpbr.v1.service.bluecrystal/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "rebuildEnvelope", namespace = "http://icpbr.v1.service.bluecrystal/", propOrder = {
    "format",
    "envelopeb64"
})
public class RebuildEnvelope {

    @XmlElement(name = "format", namespace = "")
    private int format;
    @XmlElement(name = "envelopeb64", namespace = "")
    private String envelopeb64;

    /**
     * 
     * @return
     *     returns int
     */
    public int getFormat() {
        return this.format;
    }

    /**
     * 
     * @param format
     *     the value for the format property
     */
    public void setFormat(int format) {
        this.format = format;
    }

    /**
     * 
     * @return
     *     returns String
     */
    public String getEnvelopeb64() {
        return this.envelopeb64;
    }

    /**
     * 
     * @param envelopeb64
     *     the value for the envelopeb64 property
     */
    public void setEnvelopeb64(String envelopeb64) {
        this.envelopeb64 = envelopeb64;
    }

}
