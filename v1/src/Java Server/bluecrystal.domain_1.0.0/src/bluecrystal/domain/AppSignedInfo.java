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

public class AppSignedInfo {
	private String certId;
	private byte[] signedHash;
	private byte[] origHash;
	private Date signingTime;


	
	public AppSignedInfo(String certId, byte[] signedHash, byte[] origHash,
			Date signingTime) {
		super();
		this.certId = certId;
		this.signedHash = signedHash;
		this.origHash = origHash;
		this.signingTime = signingTime;
	}
	
	public String getCertId() {
		return certId;
	}
	public byte[] getSignedHash() {
		return signedHash;
	}
	public byte[] getOrigHash() {
		return origHash;
	}
	public Date getSigningTime() {
		return signingTime;
	}
	
	
}
