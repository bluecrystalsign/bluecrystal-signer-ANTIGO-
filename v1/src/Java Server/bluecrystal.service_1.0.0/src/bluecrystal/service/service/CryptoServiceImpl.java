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

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.DERTaggedObject;

import sun.misc.BASE64Decoder;
import bluecrystal.bcdeps.helper.DerEncoder;
import bluecrystal.domain.AppSignedInfo;
import bluecrystal.domain.AppSignedInfoEx;
import bluecrystal.domain.CertStatus;
import bluecrystal.domain.SignCompare;
import bluecrystal.domain.SignCompare2;
import bluecrystal.domain.SignPolicyRef;
import bluecrystal.domain.StatusConst;
import bluecrystal.service.loader.Messages;

public class CryptoServiceImpl implements CryptoService {
	private String validateCert = Messages
			.getString("CryptoService.validateCert");
	private static EnvelopeService serv2048;
	private static EnvelopeService serv1024;
	private static CertificateService certServ;
	private static SignVerifyService signVerifyServ;

	private static final int NDX_SHA1 = 0;
	private static final int NDX_SHA224 = 1;
	private static final int NDX_SHA256 = 2;
	private static final int NDX_SHA384 = 3;
	private static final int NDX_SHA512 = 4;

	private static final int SIGNER_ONLY = 1;
	private static final int FULL_PATH = 2;

	private static final String ID_SHA1 = "1.3.14.3.2.26";
	private static final String ID_SHA256 = "2.16.840.1.101.3.4.2.1";

	// private static final String ID_SIG_POLICY = "1.2.840.113549.1.9.16.2.15";

	public int doIt(String src) {
		return 0;
	}

	public CryptoServiceImpl() {
		super();
		serv2048 = new ADRBService_21();
		// serv2048 = new CMS3Service();
		serv1024 = new ADRBService_10();
		certServ = new CertificateService();
		signVerifyServ = new SignVerifyService();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ittru.service.CCService#hashSignedAttribSha1(byte[],
	 * java.util.Date, java.security.cert.X509Certificate)
	 */
	public byte[] hashSignedAttribSha1(byte[] origHash, Date signingTime,
			X509Certificate x509) throws Exception {
		return serv1024.hashSignedAttribSha1(origHash, signingTime, x509);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ittru.service.CCService#hashSignedAttribSha256(byte[],
	 * java.util.Date, java.security.cert.X509Certificate)
	 */
	public byte[] hashSignedAttribSha256(byte[] origHash, Date signingTime,
			X509Certificate x509) throws Exception {
		return serv2048.hashSignedAttribSha256(origHash, signingTime, x509);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ittru.service.CCService#extractSignature(byte[])
	 */
	public byte[] extractSignature(byte[] sign) throws Exception {
		return DerEncoder.extractSignature(sign);
	}

	public String extractHashId(byte[] sign) throws Exception {
		return DerEncoder.extractHashId(sign);
	}

	public SignCompare extractSignCompare(byte[] sign) throws Exception {
		SignCompare signCompare = new SignCompare();
		DERTaggedObject signedAttribsDTO = extractDTOSignPolicyOid(sign,
				signCompare);
		if (signedAttribsDTO != null) {
			extractSignPolicyRefFromSignedAttrib(signedAttribsDTO, signCompare);
		}

		return signCompare;
	}
	
	@Override
	public SignCompare2 extractSignCompare2(byte[] sign) throws Exception {
		SignCompare2 signCompare = new SignCompare2();
		DerEncoder.extractSignCompare2(sign, signCompare);
		return signCompare;
	}


	public DERTaggedObject extractDTOSignPolicyOid(byte[] sign,
			SignCompare signCompare) throws Exception {
		return DerEncoder.extractDTOSignPolicyOid(sign, signCompare);
	}

	public boolean validateSignByContent(byte[] signCms, byte[] content,
			Date dtSign, boolean verifyCRL) throws Exception {
		byte[] origHash = null;
		String hashIdStr = extractHashId(signCms);
		if (ID_SHA256.compareTo(hashIdStr) == 0) {
			origHash = calcSha256(content);
		} else {
			origHash = calcSha1(content);
		}
		return validateSign(signCms, origHash, dtSign, verifyCRL);
	}

	public boolean validateSign(byte[] signCms, byte[] origHash, Date dtSign,
			boolean verifyCRL) throws Exception {

		SignCompare signCompare = extractSignCompare(signCms);
		X509Certificate cert = certServ.decodeEE(signCms);

		boolean ret = true;
		boolean validateCertB = Boolean.parseBoolean(validateCert);
		if (validateCertB) {
			CertStatus certStatus = null;
			if (dtSign != null) {
				certStatus = certServ.isValid(dtSign, cert, verifyCRL);
			} else {
				certStatus = certServ.isValid(signCompare.getSigningTime(),
						cert, verifyCRL);
			}

			if (!(certStatus.getStatus() == StatusConst.GOOD || certStatus
					.getStatus() == StatusConst.UNKNOWN)) {
				return false;
			}
		}
		String hashIdStr = extractHashId(signCms);
		byte[] sign = extractSignature(signCms);

		int hashId = NDX_SHA1;

		// byte[] origHash = null;
		byte[] hashSa = null;
		byte[] contentHash = null;

		if (ID_SHA256.compareTo(hashIdStr) == 0) {
			hashId = NDX_SHA256;
			// origHash = calcSha256(content);
			if (signCompare.getSignedAttribs() == null
					|| signCompare.getSignedAttribs().size() == 0) {
				contentHash = origHash;
			} else {
				hashSa = hashSignedAttribSha256(origHash,
						signCompare.getSigningTime(), cert);
				contentHash = calcSha256(hashSa);
			}

		} else {

			// origHash = calcSha1(content);
			if (signCompare.getSignedAttribs() == null
					|| signCompare.getSignedAttribs().size() == 0) {
				contentHash = origHash;
			} else {
				hashSa = hashSignedAttribSha1(origHash,
						signCompare.getSigningTime(), cert);
				contentHash = calcSha1(hashSa);
			}
		}
		ret = signVerifyServ.verify(hashId, contentHash, sign, cert);

		return ret;
	}


	public boolean validateSignatureByPolicy(SignPolicyRef spr, SignCompare sc) {

		boolean isNotBefore = sc.getSigningTime().after(spr.getNotBefore());
		boolean isNotAfter = sc.getSigningTime().before(spr.getNotAfter());

		List<String> sprAttr = spr.getMandatedSignedAttr();
		List<String> scAttr = sc.getSignedAttribs();
		boolean attrOk = true;
		for (String next : sprAttr) {
			if (!scAttr.contains(next)) {
				attrOk = false;
			}
		}

		boolean isMcr = true;
		if (spr.getMandatedCertificateRef() == SIGNER_ONLY) {
			isMcr = sc.getNumCerts() == 1 ? true : false;

		} else if (spr.getMandatedCertificateRef() == FULL_PATH) {
			isMcr = sc.getNumCerts() > 1 ? true : false;
			// TODO: validate full path
		}

		boolean isPolOid = spr.getPsOid().compareTo(sc.getPsOid()) == 0;

		return isNotBefore && isNotAfter && attrOk && isMcr && isPolOid;
	}

	private void extractSignPolicyRefFromSignedAttrib(
			DERTaggedObject signedAttribsDTO, SignCompare signCompare)
			throws Exception {
		DerEncoder.extractSignPolicyRefFromSignedAttrib(signedAttribsDTO,
				signCompare);
	}

	public SignPolicyRef extractVerifyRefence(byte[] policy)
			throws IOException, ParseException {
		return DerEncoder.extractVerifyRefence(policy);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ittru.service.CCService#composeBodySha1(byte[],
	 * java.security.cert.X509Certificate, byte[], java.util.Date)
	 */
	public byte[] composeBodySha1(byte[] sign, X509Certificate c,
			byte[] origHash, Date signingTime) throws Exception {
		byte[] ret = null;

		int idSha = NDX_SHA1;
		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
		List<X509Certificate> chain = new ArrayList<X509Certificate>();

		byte[] certHash = calcSha1(c.getEncoded());

		AppSignedInfoEx asiEx = new AppSignedInfoEx(sign, origHash,
				signingTime, c, certHash, idSha);
		listAsiEx.add(asiEx);

		ret = serv1024.buildCms(listAsiEx, -1);

		return ret;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ittru.service.CCService#composeBodySha256(byte[],
	 * java.security.cert.X509Certificate, byte[], java.util.Date)
	 */
	public byte[] composeBodySha256(byte[] sign, X509Certificate c,
			byte[] origHash, Date signingTime) throws Exception {
		byte[] ret = null;

		int idSha = NDX_SHA256;
		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
//		List<X509Certificate> chain = new ArrayList<X509Certificate>();

		byte[] certHash = calcSha256(c.getEncoded());

		AppSignedInfoEx asiEx = new AppSignedInfoEx(sign, origHash,
				signingTime, c, certHash, idSha);
		listAsiEx.add(asiEx);

		ret = serv2048.buildCms(listAsiEx, -1);

		return ret;
	}

	
	public byte[] composeBodySha256(List<AppSignedInfo> listAsi) throws Exception {
		byte[] ret = null;

		int idSha = NDX_SHA256;
		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
//		List<X509Certificate> chain = new ArrayList<X509Certificate>();
		BASE64Decoder b64dec = new BASE64Decoder();
		for (AppSignedInfo appSignedInfo : listAsi) {
			// AppSignedInfo appSignedInfo = listAsi.get(0);
			byte[] x509 = b64dec.decodeBuffer(appSignedInfo.getCertId());
			X509Certificate cert = loadCert(x509);
			byte[] certHash = calcSha256(cert.getEncoded());
			AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, cert,
					certHash, idSha);
			listAsiEx.add(asiEx);
		}

		ret = serv2048.buildCms(listAsiEx, -1);

		return ret;
	}
	
	private X509Certificate loadCert(byte[] certEnc)
			throws FileNotFoundException, CertificateException, IOException {
		InputStream is = new ByteArrayInputStream(certEnc);
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		X509Certificate c = (X509Certificate) cf.generateCertificate(is);
		is.close();
		return c;
	}
	
	public byte[] calcSha1(byte[] content) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA1");
		md.reset();
		md.update(content);
		byte[] output = md.digest();
		return output;
	}

	public byte[] calcSha256(byte[] content) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA256");
		md.reset();
		md.update(content);
		byte[] output = md.digest();
		return output;
	}
}
