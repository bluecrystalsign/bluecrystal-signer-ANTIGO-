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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import bluecrystal.bcdeps.helper.DerEncoder;
import bluecrystal.bcdeps.helper.PkiOps;
import bluecrystal.domain.AppSignedInfo;
import bluecrystal.domain.AppSignedInfoEx;
import bluecrystal.domain.SignPolicy;
import bluecrystal.domain.helper.IttruLoggerFactory;
import bluecrystal.service.helper.Utils;

public abstract class BaseService implements EnvelopeService {
	static final Logger LOG = LoggerFactory.getLogger(BaseService.class);
	public BaseService() {
		super();
		procHash = true;
	}

	public boolean isProcHash() {
		return procHash;
	}

	protected static final String SIG_POLICY_URI = "http://politicas.icpbrasil.gov.br/PA_AD_RB.der";
	protected static final String SIG_POLICY_BES_ID = "2.16.76.1.7.1.1.1";
	protected static final String SIG_POLICY_HASH = "20d6789325513bbc8c29624e1f40b61813ec5ce7";

	
	
	protected static final String SIG_POLICY_URI_20 = "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_0.der";
	protected static final String SIG_POLICY_BES_ID_20 = "2.16.76.1.7.1.1.2";
	protected static final String SIG_POLICY_HASH_20 = "5311e6ce55665c877608"
			+ "5ef11c82fa3fb1341cad" + "e7981ed9f51d3e56de5f" + "6aad";

	protected static final String SIG_POLICY_URI_21 = "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_1.der";
	protected static final String SIG_POLICY_BES_ID_21 = "2.16.76.1.7.1.1.2.1";
	protected static final String SIG_POLICY_HASH_21 = "dd57c98a4313bc1398ce"
			+ "6543d3802458957cf716" + "ae3294ec4d8c26251291" + "e6c1";
	protected static final int NDX_SHA1 = 0;
	protected static final int NDX_SHA224 = 1;
	protected static final int NDX_SHA256 = 2;
	protected static final int NDX_SHA384 = 3;
	protected static final int NDX_SHA512 = 4;

	protected int version;
	protected int minKeyLen;
	protected boolean signedAttr;
	protected boolean signingCertFallback;
	protected boolean addChain;
	protected boolean procHash;

	protected byte[] policyHash;
	protected String policyUri;
	protected String policyId;

	protected static PkiOps pkiOps;
	protected static CertificateService certServ;

	static {
		pkiOps = new PkiOps();
		certServ = new CertificateService();
	};

	protected boolean isSigningCertFallback() {
		return signingCertFallback;
	}

	protected boolean isSignedAttr() {
		return signedAttr;
	}
	
	public byte[] rebuildEnvelope(byte[] envelopeb64) throws Exception{
		throw new UnsupportedOperationException();
	}

	public byte[] calcSha1(byte[] content) throws NoSuchAlgorithmException {
		return pkiOps.calcSha1(content);
	}

	public byte[] calcSha224(byte[] content) throws NoSuchAlgorithmException {
		return pkiOps.calcSha224(content);
	}

	public byte[] calcSha256(byte[] content) throws NoSuchAlgorithmException {
		return pkiOps.calcSha256(content);
	}

	public byte[] calcSha384(byte[] content) throws NoSuchAlgorithmException {
		return pkiOps.calcSha384(content);
	}

	public byte[] calcSha512(byte[] content) throws NoSuchAlgorithmException {
		return pkiOps.calcSha512(content);
	}

//	public byte[] hashSignedAttribSha1(String certId, byte[] origHash,
//			Date signingTime) throws Exception {
//		X509Certificate x509 = Utils.loadCertFromS3(certId);
//		return hashSignedAttribSha1(origHash, signingTime, x509);
//
//	}

	public byte[] hashSignedAttribSha1(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException {
		if (signedAttr) {
			DerEncoder derEnc = new DerEncoder();

			byte[] certHash = pkiOps.calcSha1(x509.getEncoded());
			int idSha = NDX_SHA1;
			ASN1Set newSi = siCreate(origHash, signingTime, x509, derEnc,
					certHash, idSha);

			byte[] saAsBytes = convSiToByte(newSi);
			byte[] saAsBytes2 = hackSi(saAsBytes);
			return saAsBytes2;
		}
		return origHash;
	}

	@Override
	public byte[] buildFromS3Sha1(List<AppSignedInfo> listAsi, int attachSize) throws Exception {
		int idSha = NDX_SHA1;
		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
		List<X509Certificate> chain = new ArrayList<X509Certificate>();

		for (AppSignedInfo appSignedInfo : listAsi) {
			// AppSignedInfo appSignedInfo = listAsi.get(0);
			X509Certificate x509 = loadCert(appSignedInfo);
			chain.addAll(certServ.buildPath(x509));
			byte[] certHash = pkiOps.calcSha1(x509.getEncoded());
			AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, x509,
					certHash, idSha);
			listAsiEx.add(asiEx);
		}

		dedup(chain);
		byte[] cmsOut = buildBody(chain, listAsiEx, attachSize);
		return cmsOut;
	}
	

	public byte[] buildCms(List<AppSignedInfoEx> listAsiEx, int attachSize) throws Exception {
		List<X509Certificate> chain = new ArrayList<X509Certificate>();

		for (AppSignedInfoEx appSignedInfo : listAsiEx) {
			// AppSignedInfo appSignedInfo = listAsi.get(0);
			X509Certificate x509 = appSignedInfo.getX509();
//			chain.addAll(certServ.buildPath(x509));
			chain.addAll(certServ.buildPath(x509));
		}

		dedup(chain);
		byte[] cmsOut = buildBody(chain, listAsiEx, attachSize);
		return cmsOut;
		
	}
	
	public byte[] buildSha256(List<AppSignedInfoEx> listAsiEx, int attachSize) throws Exception {
		List<X509Certificate> chain = new ArrayList<X509Certificate>();

		for (AppSignedInfoEx appSignedInfo : listAsiEx) {
			// AppSignedInfo appSignedInfo = listAsi.get(0);
			X509Certificate x509 = appSignedInfo.getX509();
			chain.addAll(certServ.buildPath(x509));
			byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
					.getEncoded()) : pkiOps.calcSha256(x509.getEncoded());
		}

		dedup(chain);
		byte[] cmsOut = buildBody(chain, listAsiEx, attachSize);
		return cmsOut;
		
	}
	
	private void dedup(List<X509Certificate> list) {
		Map<String, X509Certificate> map = new HashMap<String, X509Certificate>();
		Iterator<X509Certificate> it = list.iterator();

		while (it.hasNext()) {
			X509Certificate nextCert = it.next();
			map.put(nextCert.getSubjectDN().getName(), nextCert);
		}
		
		list.clear();
		for(X509Certificate next : map.values()){
			list.add(next);
		}
		
	}

//	public byte[] hashSignedAttribSha224(String certId, byte[] origHash,
//			Date signingTime) throws Exception {
//		X509Certificate x509 = Utils.loadCertFromRepo(certId);
//		return hashSignedAttribSha224(origHash, signingTime, x509);
//
//	}

	public byte[] hashSignedAttribSha224(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException {
		if (signedAttr) {
			DerEncoder derEnc = new DerEncoder();

			byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
					.getEncoded()) : pkiOps.calcSha224(x509.getEncoded());
			int idSha = NDX_SHA224;
			ASN1Set newSi = siCreate(origHash, signingTime, x509, derEnc,
					certHash, idSha);

			byte[] saAsBytes = convSiToByte(newSi);
			byte[] saAsBytes2 = hackSi(saAsBytes);
			return saAsBytes2;
		}
		return origHash;
	}

//	public byte[] buildFromS3Sha224(List<AppSignedInfo> listAsi)
//			throws Exception {
//		AppSignedInfo appSignedInfo = listAsi.get(0);
//		X509Certificate x509 = Utils.loadCertFromRepo(appSignedInfo.getCertId());
//		byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
//				.getEncoded()) : pkiOps.calcSha224(x509.getEncoded());
//
//		int idSha = NDX_SHA224;
//
//		List<X509Certificate> chain = certServ.buildPath(x509);
//
//		AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, x509,
//				certHash, idSha);
//		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
//		listAsiEx.add(asiEx);
//
//		byte[] cmsOut = buildBody(chain, listAsiEx);
//		return cmsOut;
//	}

	public byte[] buildFromS3Sha224(List<AppSignedInfo> listAsi, int attachSize) throws Exception {
		int idSha = NDX_SHA224;
		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
		List<X509Certificate> chain = new ArrayList<X509Certificate>();

		for (AppSignedInfo appSignedInfo : listAsi) {
			// AppSignedInfo appSignedInfo = listAsi.get(0);
			X509Certificate x509 = loadCert(appSignedInfo);
			chain.addAll(certServ.buildPath(x509));
			byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
			.getEncoded()) : pkiOps.calcSha224(x509.getEncoded());
			AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, x509,
					certHash, idSha);
			listAsiEx.add(asiEx);
		}

		dedup(chain);
		byte[] cmsOut = buildBody(chain, listAsiEx, attachSize );
		return cmsOut;
	}
	
	
//	public byte[] hashSignedAttribSha256(String certId, byte[] origHash,
//			Date signingTime) throws Exception {
//		X509Certificate x509 = Utils.loadCertFromS3(certId);
//		return hashSignedAttribSha256(origHash, signingTime, x509);
//	}

	public byte[] hashSignedAttribSha256(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException {
		if (signedAttr) {
			DerEncoder derEnc = new DerEncoder();

			byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
					.getEncoded()) : pkiOps.calcSha256(x509.getEncoded());

			int idSha = NDX_SHA256;
			ASN1Set newSi = siCreate(origHash, signingTime, x509, derEnc,
					certHash, idSha);

			byte[] saAsBytes = convSiToByte(newSi);
			byte[] saAsBytes2 = hackSi(saAsBytes);

			return saAsBytes2;
		}
		return origHash;
	}

//	public byte[] buildFromS3Sha256(List<AppSignedInfo> listAsi)
//			throws Exception {
//		AppSignedInfo appSignedInfo = listAsi.get(0);
//		X509Certificate x509 = Utils.loadCertFromS3(appSignedInfo.getCertId());
//		byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
//				.getEncoded()) : pkiOps.calcSha256(x509.getEncoded());
//
//		int idSha = NDX_SHA256;
//
//		List<X509Certificate> chain = certServ.buildPath(x509);
//
//		AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, x509,
//				certHash, idSha);
//		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
//		listAsiEx.add(asiEx);
//
//		byte[] cmsOut = buildBody(chain, listAsiEx);
//		return cmsOut;
//	}

	
	public byte[] buildFromS3Sha256(List<AppSignedInfo> listAsi, int attachSize) throws Exception {
		int idSha = NDX_SHA256;
		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
		List<X509Certificate> chain = new ArrayList<X509Certificate>();

		for (AppSignedInfo appSignedInfo : listAsi) {
			X509Certificate x509 = loadCert(appSignedInfo);
			chain.addAll(certServ.buildPath(x509));
			byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
			.getEncoded()) : pkiOps.calcSha256(x509.getEncoded());
			AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, x509,
					certHash, idSha);
			listAsiEx.add(asiEx);
		}

		dedup(chain);
		byte[] cmsOut = buildBody(chain, listAsiEx, attachSize);
		return cmsOut;
	}

	private X509Certificate loadCert(AppSignedInfo appSignedInfo)
			throws Exception {
		X509Certificate x509;
		try {
			x509 = Utils.createCert(Utils.convHexToByte(appSignedInfo
					.getCertId()));
		} catch (Exception e) {
			x509 = Utils.loadCertFromRepo(appSignedInfo
					.getCertId());
		}
		return x509;
	}
	
	
//	public byte[] hashSignedAttribSha384(String certId, byte[] origHash,
//			Date signingTime) throws Exception {
//		X509Certificate x509 = Utils.loadCertFromS3(certId);
//		return hashSignedAttribSha384(origHash, signingTime, x509);
//
//	}

	public byte[] hashSignedAttribSha384(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException {
		if (signedAttr) {
			DerEncoder derEnc = new DerEncoder();

			byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
					.getEncoded()) : pkiOps.calcSha384(x509.getEncoded());
			int idSha = NDX_SHA384;
			ASN1Set newSi = siCreate(origHash, signingTime, x509, derEnc,
					certHash, idSha);

			byte[] saAsBytes = convSiToByte(newSi);
			byte[] saAsBytes2 = hackSi(saAsBytes);

			return saAsBytes2;
		}
		return origHash;
	}

//	public byte[] buildFromS3Sha384(List<AppSignedInfo> listAsi)
//			throws Exception {
//		AppSignedInfo appSignedInfo = listAsi.get(0);
//		X509Certificate x509 = Utils.loadCertFromS3(appSignedInfo.getCertId());
//		byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
//				.getEncoded()) : pkiOps.calcSha384(x509.getEncoded());
//
//		int idSha = NDX_SHA384;
//
//		List<X509Certificate> chain = certServ.buildPath(x509);
//
//		AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, x509,
//				certHash, idSha);
//		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
//		listAsiEx.add(asiEx);
//
//		byte[] cmsOut = buildBody(chain, listAsiEx);
//		return cmsOut;
//	}
	
	public byte[] buildFromS3Sha384(List<AppSignedInfo> listAsi, int attachSize) throws Exception {
		int idSha = NDX_SHA384;
		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
		List<X509Certificate> chain = new ArrayList<X509Certificate>();

		for (AppSignedInfo appSignedInfo : listAsi) {
			// AppSignedInfo appSignedInfo = listAsi.get(0);
			X509Certificate x509 = loadCert(appSignedInfo);
			chain.addAll(certServ.buildPath(x509));
			byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
			.getEncoded()) : pkiOps.calcSha384(x509.getEncoded());
			AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, x509,
					certHash, idSha);
			listAsiEx.add(asiEx);
		}

		dedup(chain);
		byte[] cmsOut = buildBody(chain, listAsiEx, attachSize);
		return cmsOut;
	}	

//	public byte[] hashSignedAttribSha512(String certId, byte[] origHash,
//			Date signingTime) throws Exception {
//		X509Certificate x509 = Utils.loadCertFromS3(certId);
//		return hashSignedAttribSha512(origHash, signingTime, x509);
//
//	}

	public byte[] hashSignedAttribSha512(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException {
		if (signedAttr) {
			DerEncoder derEnc = new DerEncoder();

			byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
					.getEncoded()) : pkiOps.calcSha512(x509.getEncoded());
			int idSha = NDX_SHA512;
			ASN1Set newSi = siCreate(origHash, signingTime, x509, derEnc,
					certHash, idSha);

			byte[] saAsBytes = convSiToByte(newSi);
			byte[] saAsBytes2 = hackSi(saAsBytes);
			return saAsBytes2;
		}
		return origHash;
	}

//	public byte[] buildFromS3Sha512(List<AppSignedInfo> listAsi)
//			throws Exception {
//		AppSignedInfo appSignedInfo = listAsi.get(0);
//		X509Certificate x509 = Utils.loadCertFromS3(appSignedInfo.getCertId());
//		byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
//				.getEncoded()) : pkiOps.calcSha512(x509.getEncoded());
//
//		int idSha = NDX_SHA512;
//
//		List<X509Certificate> chain = certServ.buildPath(x509);
//
//		AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, x509,
//				certHash, idSha);
//		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
//		listAsiEx.add(asiEx);
//
//		byte[] cmsOut = buildBody(chain, listAsiEx);
//		return cmsOut;
//	}

	public byte[] buildFromS3Sha512(List<AppSignedInfo> listAsi, int attachSize) throws Exception {
		int idSha = NDX_SHA512;
		List<AppSignedInfoEx> listAsiEx = new ArrayList<AppSignedInfoEx>();
		List<X509Certificate> chain = new ArrayList<X509Certificate>();

		for (AppSignedInfo appSignedInfo : listAsi) {
			// AppSignedInfo appSignedInfo = listAsi.get(0);
			X509Certificate x509 = loadCert(appSignedInfo);
			chain.addAll(certServ.buildPath(x509));
			byte[] certHash = signingCertFallback ? pkiOps.calcSha1(x509
			.getEncoded()) : pkiOps.calcSha512(x509.getEncoded());
			AppSignedInfoEx asiEx = new AppSignedInfoEx(appSignedInfo, x509,
					certHash, idSha);
			listAsiEx.add(asiEx);
		}

		dedup(chain);
		byte[] cmsOut = buildBody(chain, listAsiEx, attachSize);
		return cmsOut;
	}		
	
	// TODO
	// MOVER DER ENCODER :)
	private byte[] hackSi(byte[] saAsBytes) throws IOException {
		LOG.debug(Utils.conv(saAsBytes));

		byte[] saAsBytes2 = new byte[saAsBytes.length - 4];

		saAsBytes2[0] = saAsBytes[0];
		saAsBytes2[1] = saAsBytes[1];
		for (int i = 2; i < saAsBytes2.length; i++) {
			saAsBytes2[i] = saAsBytes[i + 4];
		}
		LOG.debug(Utils.conv(saAsBytes2));
		return saAsBytes2;
	}

	public ASN1Set siCreate(byte[] origHash, Date signingTime,
			X509Certificate x509, DerEncoder derEnc, byte[] certHash, int idSha)
			throws Exception {
		return derEnc.siCreateDerEncSignedADRB(origHash, policyHash, certHash,
				x509, signingTime, idSha, policyUri, policyId,
				signingCertFallback);
	}

	private byte[] buildBody(List<X509Certificate> chain,
			List<AppSignedInfoEx> listAsiEx, int attachSize) throws Exception {

		byte[] cmsOut = null;
		DerEncoder de = new DerEncoder();
		SignPolicy signPol = new SignPolicy(policyHash, policyUri, policyId);
		if (signedAttr) {
			cmsOut = de.buildADRBBody(listAsiEx, signPol, addChain ? chain
					: null, version, signingCertFallback, attachSize);
		} else {
			AppSignedInfoEx asiEx = listAsiEx.get(0);
			cmsOut = de.buildCmsBody(asiEx.getSignedHash(), asiEx.getX509(),
					addChain ? chain : null, asiEx.getIdSha(), version, attachSize);
		}
		return cmsOut;
	}



	private static byte[] convSiToByte(ASN1Set newSi) throws IOException {
	return DerEncoder.convSiToByte(newSi);
}
	
	
	
}
