package bluecrystal.domain;

import java.util.Date;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement (name="Signature")
public class Signature {
	@XmlElement
	private String signB64;
	
	@XmlElement
	private String x509B64;
	
	@XmlElement
	private String origHashB64;
	
	@XmlElement
	private Date signingTime;
	
	public String getSignB64() {
		return signB64;
	}
	public String getX509B64() {
		return x509B64;
	}
	public String getOrigHashB64() {
		return origHashB64;
	}
	public Date getSigningTime() {
		return signingTime;
	}
	public Signature(String signB64, String x509b64, String origHashB64,
			Date signingTime) {
		super();
		this.signB64 = signB64;
		x509B64 = x509b64;
		this.origHashB64 = origHashB64;
		this.signingTime = signingTime;
	}
	public Signature() {
		super();
		
	}
	
}
