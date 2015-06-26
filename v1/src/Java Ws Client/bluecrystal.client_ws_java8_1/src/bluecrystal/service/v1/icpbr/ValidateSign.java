
package bluecrystal.service.v1.icpbr;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Classe Java de validateSign complex type.
 * 
 * <p>O seguinte fragmento do esquema especifica o conteúdo esperado contido dentro desta classe.
 * 
 * <pre>
 * &lt;complexType name="validateSign">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="signCmsb64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="origHashb64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="signingTime" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *         &lt;element name="verifyCrlOcsp" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "validateSign", propOrder = {
    "signCmsb64",
    "origHashb64",
    "signingTime",
    "verifyCrlOcsp"
})
public class ValidateSign {

    protected String signCmsb64;
    protected String origHashb64;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar signingTime;
    protected boolean verifyCrlOcsp;

    /**
     * Obtém o valor da propriedade signCmsb64.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSignCmsb64() {
        return signCmsb64;
    }

    /**
     * Define o valor da propriedade signCmsb64.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignCmsb64(String value) {
        this.signCmsb64 = value;
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

    /**
     * Obtém o valor da propriedade verifyCrlOcsp.
     * 
     */
    public boolean isVerifyCrlOcsp() {
        return verifyCrlOcsp;
    }

    /**
     * Define o valor da propriedade verifyCrlOcsp.
     * 
     */
    public void setVerifyCrlOcsp(boolean value) {
        this.verifyCrlOcsp = value;
    }

}
