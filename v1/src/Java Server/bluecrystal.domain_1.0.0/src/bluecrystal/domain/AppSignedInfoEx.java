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

import java.security.cert.X509Certificate;
import java.util.Date;

public class AppSignedInfoEx extends AppSignedInfo {
	
	X509Certificate x509;
	byte[] certHash;
	int idSha;

	public AppSignedInfoEx(AppSignedInfo asi, X509Certificate x509, byte[] certHash, int idSha) {
		super(asi.getCertId(), asi.getSignedHash(), asi.getOrigHash(), asi.getSigningTime());
		this.x509 = x509;
		this.certHash = certHash;
		this.idSha = idSha;
	}
	
	public AppSignedInfoEx(byte[] signedHash, byte[] origHash,
			Date signingTime, X509Certificate x509, byte[] certHash, int idSha) {
		super(null, signedHash, origHash, signingTime);
		this.x509 = x509;
		this.certHash = certHash;
		this.idSha = idSha;
	}
	

	public X509Certificate getX509() {
		return x509;
	}

	public byte[] getCertHash() {
		return certHash;
	}

	public int getIdSha() {
		return idSha;
	}

}
