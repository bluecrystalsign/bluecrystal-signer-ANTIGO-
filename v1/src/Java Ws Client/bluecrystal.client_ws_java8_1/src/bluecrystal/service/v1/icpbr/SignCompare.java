
package bluecrystal.service.v1.icpbr;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Classe Java de signCompare complex type.
 * 
 * <p>O seguinte fragmento do esquema especifica o conteúdo esperado contido dentro desta classe.
 * 
 * <pre>
 * &lt;complexType name="signCompare">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="numCerts" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="psOid" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="psUrl" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="signedAttribs" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/>
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
@XmlType(name = "signCompare", propOrder = {
    "numCerts",
    "psOid",
    "psUrl",
    "signedAttribs",
    "signingTime"
})
public class SignCompare {

    protected int numCerts;
    protected String psOid;
    protected String psUrl;
    @XmlElement(nillable = true)
    protected List<String> signedAttribs;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar signingTime;

    /**
     * Obtém o valor da propriedade numCerts.
     * 
     */
    public int getNumCerts() {
        return numCerts;
    }

    /**
     * Define o valor da propriedade numCerts.
     * 
     */
    public void setNumCerts(int value) {
        this.numCerts = value;
    }

    /**
     * Obtém o valor da propriedade psOid.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPsOid() {
        return psOid;
    }

    /**
     * Define o valor da propriedade psOid.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPsOid(String value) {
        this.psOid = value;
    }

    /**
     * Obtém o valor da propriedade psUrl.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPsUrl() {
        return psUrl;
    }

    /**
     * Define o valor da propriedade psUrl.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPsUrl(String value) {
        this.psUrl = value;
    }

    /**
     * Gets the value of the signedAttribs property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the signedAttribs property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSignedAttribs().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getSignedAttribs() {
        if (signedAttribs == null) {
            signedAttribs = new ArrayList<String>();
        }
        return this.signedAttribs;
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
