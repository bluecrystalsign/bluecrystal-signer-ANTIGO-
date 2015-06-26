
package bluecrystal.service.v1.icpbr;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Classe Java de validateSignatureByPolicy complex type.
 * 
 * <p>O seguinte fragmento do esquema especifica o conteúdo esperado contido dentro desta classe.
 * 
 * <pre>
 * &lt;complexType name="validateSignatureByPolicy">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="signCmsb64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="psb64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "validateSignatureByPolicy", propOrder = {
    "signCmsb64",
    "psb64"
})
public class ValidateSignatureByPolicy {

    protected String signCmsb64;
    protected String psb64;

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
     * Obtém o valor da propriedade psb64.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPsb64() {
        return psb64;
    }

    /**
     * Define o valor da propriedade psb64.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPsb64(String value) {
        this.psb64 = value;
    }

}
