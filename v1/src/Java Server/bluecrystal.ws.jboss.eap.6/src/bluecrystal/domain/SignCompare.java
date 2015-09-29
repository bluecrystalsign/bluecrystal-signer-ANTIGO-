package bluecrystal.domain;


import java.util.Date;
import java.util.List;

public class SignCompare {
	@Override
	public String toString() {
		return String
				.format("SignCompare [signingTime=%s,\nnumCerts=%s,\nsignedAttribs=%s,\npsOid=%s,\npsUrl=%s]",
						signingTime, numCerts, signedAttribs, psOid, psUrl);
	}
	private Date signingTime;
	private int numCerts;
	private List<String> signedAttribs;
	private String psOid;
	private String psUrl;
	public Date getSigningTime() {
		return signingTime;
	}
	public void setSigningTime(Date signingTime) {
		this.signingTime = signingTime;
	}
	public int getNumCerts() {
		return numCerts;
	}
	public void setNumCerts(int numCerts) {
		this.numCerts = numCerts;
	}
	public List<String> getSignedAttribs() {
		return signedAttribs;
	}
	public void setSignedAttribs(List<String> signedAttribs) {
		this.signedAttribs = signedAttribs;
	}
	public String getPsOid() {
		return psOid;
	}
	public void setPsOid(String psOid) {
		this.psOid = psOid;
	}
	public String getPsUrl() {
		return psUrl;
	}
	public void setPsUrl(String psUrl) {
		this.psUrl = psUrl;
	}
	

}
