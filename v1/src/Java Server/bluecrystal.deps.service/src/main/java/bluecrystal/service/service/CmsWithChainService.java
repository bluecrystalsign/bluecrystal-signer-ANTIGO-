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

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.List;

import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.util.DerOutputStream;
import sun.security.x509.AlgorithmId;

public class CmsWithChainService extends BaseService {
	private CryptoService cryptoServ = null;
	private CertificateService certServ = null;

	public CmsWithChainService() {
		super();
		minKeyLen = 1024;
		signingCertFallback = false;
		addChain = true;
		signedAttr = false;
		version = 1;
		policyHash = null;
		policyId = null;
		policyUri = null;
		cryptoServ = new CryptoServiceImpl();
		certServ = new CertificateService();
	}

	// @Override
	// public byte[] rebuildEnvelope(byte[] envelope) throws Exception {
	// int idSha = NDX_SHA1;
	// X509Certificate certEE = certServ.decodeEE(envelope);
	// List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
	// List<X509Certificate> chain = new ArrayList<X509Certificate>();
	//
	// byte[] certHash = calcSha256(certEE.getEncoded());
	//
	// SignCompare2 signCompare = cryptoServ.extractSignCompare2(envelope);
	// // AppSignedInfoEx asiEx = new AppSignedInfoEx(sign, origHash,
	// // null, certEE, certHash, idSha);
	// BASE64Decoder b64dec = new BASE64Decoder();
	// String signedHashb64 = signCompare.getSignedHashb64();
	// String origHashb64 = signCompare.getOrigHashb64();
	// Date signingTime = signCompare.getSigningTime();
	// AppSignedInfoEx asiEx = new
	// AppSignedInfoEx(b64dec.decodeBuffer(signedHashb64),
	// b64dec.decodeBuffer(origHashb64), signingTime, certEE, certHash, idSha);
	// listAsiEx.add(asiEx);
	// byte[] ret = this.buildCms(listAsiEx, -1);
	// return ret;
	// }

	@Override
	public byte[] rebuildEnvelope(byte[] envelope) throws Exception {
		// CMSSignedData cms = new CMSSignedData(envelope);
		// cms.
		//
		// SignerInformationStore signers = cms.getSignerInfos();
		//
		// Collection c = signers.getSigners();
		// Iterator it = c.iterator();
		//
		// while (it.hasNext()) {
		// SignerInformation signer = (SignerInformation) it.next();
		// SignerId sid = signer.getSID();
		//
		// Store certs = cms.getCertificates();
		// Collection certCollection = certs.getMatches(signer.getSID());
		// for (Object next : certCollection) {
		// System.out.println(next);
		// }
		// }

		PKCS7 pkcs7 = new PKCS7(envelope);
		X509Certificate[] certs = pkcs7.getCertificates();
		if (certs.length == 1) {
			List<X509Certificate> path = certServ.buildPath(certs[0]);
			SignerInfo[] si = pkcs7.getSignerInfos();
			// for(X509Certificate next : path){
			// System.out.println(next.getSubjectDN().getName());
			//
			// }
			ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID,
					null);
			AlgorithmId digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid);
			X509Certificate[] pathArray = new X509Certificate[path.size()];
			int i = 0;
			for (X509Certificate next : path) {
				pathArray[i] = next;
				i++;

			}
			// Create PKCS7 Signed data
			PKCS7 p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId },
					cInfo, pathArray, si);
			// Write PKCS7 to bYteArray
			ByteArrayOutputStream bOut = new DerOutputStream();
			p7.encodeSignedData(bOut);
			byte[] encodedPKCS7 = bOut.toByteArray();
			return encodedPKCS7;
		}

		return envelope;
	}
}
