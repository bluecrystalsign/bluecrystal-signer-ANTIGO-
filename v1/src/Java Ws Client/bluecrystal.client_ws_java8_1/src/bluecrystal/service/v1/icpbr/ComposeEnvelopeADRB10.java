
package bluecrystal.service.v1.icpbr;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Classe Java de composeEnvelopeADRB10 complex type.
 * 
 * <p>O seguinte fragmento do esquema especifica o conteúdo esperado contido dentro desta classe.
 * 
 * <pre>
 * &lt;complexType name="composeEnvelopeADRB10">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="signB64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="certb64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="origHashb64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
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
@XmlType(name = "composeEnvelopeADRB10", propOrder = {
    "signB64",
    "certb64",
    "origHashb64",
    "signingTime"
})
public class ComposeEnvelopeADRB10 {

    protected String signB64;
    protected String certb64;
    protected String origHashb64;
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
     * Obtém o valor da propriedade certb64.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCertb64() {
        return certb64;
    }

    /**
     * Define o valor da propriedade certb64.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCertb64(String value) {
        this.certb64 = value;
    }

    /**
     * Obtém o valor da propriedade origHashb64.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOrigHashb64() {
        return origHashb64;
    }

    /**
     * Define o valor da propriedade origHashb64.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOrigHashb64(String value) {
        this.origHashb64 = value;
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
