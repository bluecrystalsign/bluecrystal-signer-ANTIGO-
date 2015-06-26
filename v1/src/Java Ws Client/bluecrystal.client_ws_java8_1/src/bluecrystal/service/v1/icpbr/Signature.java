
package bluecrystal.service.v1.icpbr;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Classe Java de signature complex type.
 * 
 * <p>O seguinte fragmento do esquema especifica o conteúdo esperado contido dentro desta classe.
 * 
 * <pre>
 * &lt;complexType name="signature">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="signB64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="x509B64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="origHashB64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="signingTime" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "signature", propOrder = {
    "signB64",
    "x509B64",
    "origHashB64",
    "signingTime"
})
public class Signature {

    protected String signB64;
    protected String x509B64;
    protected String origHashB64;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar signingTime;

    /**
     * Obtém o valor da propriedade signB64.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSignB64() {
        return signB64;
    }

    /**
     * Define o valor da propriedade signB64.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignB64(String value) {
        this.signB64 = value;
    }

    /**
     * Obtém o valor da propriedade x509B64.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getX509B64() {
        return x509B64;
    }

    /**
     * Define o valor da propriedade x509B64.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setX509B64(String value) {
        this.x509B64 = value;
    }

    /**
     * Obtém o valor da propriedade origHashB64.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOrigHashB64() {
        return origHashB64;
    }

    /**
     * Define o valor da propriedade origHashB64.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOrigHashB64(String value) {
        this.origHashB64 = value;
    }

    /**
     * Obtém o valor da propriedade signingTime.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getSigningTime() {
        return signingTime;
    }

    /**
     * Define o valor da propriedade signingTime.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setSigningTime(XMLGregorianCalendar value) {
        this.signingTime = value;
    }

}
