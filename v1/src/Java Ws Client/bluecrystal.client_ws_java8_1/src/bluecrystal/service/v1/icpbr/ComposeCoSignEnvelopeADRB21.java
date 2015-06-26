
package bluecrystal.service.v1.icpbr;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Classe Java de composeCoSignEnvelopeADRB21 complex type.
 * 
 * <p>O seguinte fragmento do esquema especifica o conteúdo esperado contido dentro desta classe.
 * 
 * <pre>
 * &lt;complexType name="composeCoSignEnvelopeADRB21">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="signatute" type="{http://icpbr.v1.service.bluecrystal/}signature" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "composeCoSignEnvelopeADRB21", propOrder = {
    "signatute"
})
public class ComposeCoSignEnvelopeADRB21 {

    @XmlElement(nillable = true)
    protected List<Signature> signatute;

    /**
     * Gets the value of the signatute property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the signatute property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSignatute().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Signature }
     * 
     * 
     */
    public List<Signature> getSignatute() {
        if (signatute == null) {
            signatute = new ArrayList<Signature>();
        }
        return this.signatute;
    }

}
