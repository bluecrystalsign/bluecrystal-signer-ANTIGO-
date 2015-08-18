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

package bluecrystal.service.service;



import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Set;

import bluecrystal.bcdeps.helper.DerEncoder;
import bluecrystal.service.helper.Utils;

public class ADRBService_10 extends BaseService {

	public ASN1Set siCreate(byte[] origHash, Date signingTime,
			X509Certificate x509, DerEncoder derEnc, byte[] certHash, int idSha)
			throws Exception {
		return derEnc.siCreateDerEncSignedADRB(origHash, policyHash, certHash,
				x509, signingTime, idSha, policyUri, policyId,
				signingCertFallback);
	}
	
	public ADRBService_10() {
		super();
		minKeyLen = 1024;
		addChain = false;
		signingCertFallback = true;
		signedAttr = true;
		version = 3;
		policyHash = Utils
				.convHexToByte(SIG_POLICY_HASH);
		policyId = SIG_POLICY_BES_ID;
		policyUri = SIG_POLICY_URI;
	}
}
