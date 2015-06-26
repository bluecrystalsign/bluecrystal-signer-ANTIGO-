
package bluecrystal.service.v1.icpbr;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Classe Java de parseCertificate complex type.
 * 
 * <p>O seguinte fragmento do esquema especifica o conteúdo esperado contido dentro desta classe.
 * 
 * <pre>
 * &lt;complexType name="parseCertificate">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="certb64" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "parseCertificate", propOrder = {
    "certb64"
})
public class ParseCertificate {

    protected String certb64;

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

}
