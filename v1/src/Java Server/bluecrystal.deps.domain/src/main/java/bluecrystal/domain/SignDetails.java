/*
    Blue Crystal: Document Digital Signature Tool
    Copyright (C) 2007-2015  Sergio Leal

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package bluecrystal.domain;

import java.util.Date;
import java.util.List;

public class SignDetails {
	@Override
	public String toString() {
		return String
				.format("SignCompare [signingTime=%s,\nnumCerts=%s,\nsignedAttribs=%s,\npsOid=%s,\npsUrl=%s]",
						signingTime, numCerts, signedAttribs, psOid, psUrl);
	}
	
	private Date signingTime;
	private int numCerts;
	private String[] signedAttribs;
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
	public String[] getSignedAttribs() {
		return signedAttribs;
	}
	public void setSignedAttribs(String[] signedAttribs) {
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
