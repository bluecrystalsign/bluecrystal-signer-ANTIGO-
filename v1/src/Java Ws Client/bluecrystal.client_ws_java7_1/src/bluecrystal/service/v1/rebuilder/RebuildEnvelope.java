
package bluecrystal.service.v1.rebuilder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for rebuildEnvelope complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="rebuildEnvelope">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="format" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="envelopeb64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "rebuildEnvelope", propOrder = {
    "format",
    "envelopeb64"
})
public class RebuildEnvelope {

    protected int format;
    protected String envelopeb64;

    /**
     * Gets the value of the format property.
     * 
     */
    public int getFormat() {
        return format;
    }

    /**
     * Sets the value of the format property.
     * 
     */
    public void setFormat(int value) {
        this.format = value;
    }

    /**
     * Gets the value of the envelopeb64 property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEnvelopeb64() {
        return envelopeb64;
    }

    /**
     * Sets the value of the envelopeb64 property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEnvelopeb64(String value) {
        this.envelopeb64 = value;
    }

}
