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


package bluecrystal.bcdeps.helper;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import bluecrystal.domain.AppSignedInfoEx;
import bluecrystal.domain.CertConstants;
import bluecrystal.domain.SignCompare;
import bluecrystal.domain.SignPolicy;
import bluecrystal.domain.SignPolicyRef;
import bluecrystal.domain.helper.IttruLoggerFactory;

public class DerEncoder {
	static final Logger LOG = LoggerFactory.getLogger(DerEncoder.class);

	private static final String DER = "DER";
	private static final int DETACHED = -1;
	private static final int SI_VERSION = 1;
	private static final String CMS_SIGNED_ID = "1.2.840.113549.1.7.2";
	private static final String ID_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2"; // o
																				// mesmo
																				// de
																				// cima
	private static final String ID_PKCS7_DATA = "1.2.840.113549.1.7.1";
	private static final String ID_RSA = "1.2.840.113549.1.1.1";
	private static final String ID_SHA1_RSA = "1.2.840.113549.1.1.5";
	private static final String ID_SHA256_RSA = "1.2.840.113549.1.1.11";
	private static final String ID_SHA384_RSA = "1.2.840.113549.1.1.12";
	private static final String ID_SHA512_RSA = "1.2.840.113549.1.1.13";

	private static final String ID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
	private static final String ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
	public static final String ID_SIGNING_TIME = "1.2.840.113549.1.9.5";
	private static final String ID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12";
	private static final String ID_SIGNING_CERT2 = "1.2.840.113549.1.9.16.2.47";
	public static final String ID_SIG_POLICY = "1.2.840.113549.1.9.16.2.15";
	private static final String ID_SIG_POLICY_URI = "1.2.840.113549.1.9.16.5.1";
	private static final String ID_ADBE_REVOCATION = "1.2.840.113583.1.1.8";

	private static final String ID_SHA1 = "1.3.14.3.2.26";
	private static final String ID_SHA224 = "2.16.840.1.101.3.4.2.4";
	private static final String ID_SHA256 = "2.16.840.1.101.3.4.2.1";
	private static final String ID_SHA384 = "2.16.840.1.101.3.4.2.2";
	private static final String ID_SHA512 = "2.16.840.1.101.3.4.2.3";

	public static final int NDX_SHA1 = 0;
	public static final int NDX_SHA224 = 1;
	public static final int NDX_SHA256 = 2;
	public static final int NDX_SHA384 = 3;
	public static final int NDX_SHA512 = 4;

	private static final String PF_PF_ID = "2.16.76.1.3.1";
	private static final int BIRTH_DATE_INI = 0;
	private static final int BIRTH_DATE_LEN = 8;
	private static final int CPF_INI = BIRTH_DATE_LEN;
	private static final int CPF_LEN = CPF_INI + 11;
	private static final int PIS_INI = CPF_LEN;
	private static final int PIS_LEN = PIS_INI + 11;
	private static final int RG_INI = PIS_LEN;
	private static final int RG_LEN = RG_INI + 15;
	private static final int RG_ORG_UF_INI = RG_LEN;
	private static final int RG_ORG_UF_LEN = RG_ORG_UF_INI + 6;
	private static final int RG_UF_LEN = 2;
	private static final String ICP_BRASIL_PF = "ICP-Brasil PF";
	private static final String ICP_BRASIL_PJ = "ICP-Brasil PJ";
	private static final String CERT_TYPE_FMT = "cert_type%d";
	private static final String CNPJ_OID = "2.16.76.1.3.3";
	private static final String ICP_BRASIL_PC_PREFIX_OID = "2.16.76.1.2";
	private static final String EKU_OCSP_SIGN_OID = "1.3.6.1.5.5.7.3.9";
	private static final String EKU_TIMESTAMP_OID = "1.3.6.1.5.5.7.3.8";
	private static final String EKU_IPSEC_USER_OID = "1.3.6.1.5.5.7.3.7";
	private static final String EKU_IPSEC_TUNNEL_OID = "1.3.6.1.5.5.7.3.6";
	private static final String EKU_IPSEC_END_OID = "1.3.6.1.5.5.7.3.5";
	private static final String EKU_EMAIL_PROT_OID = "1.3.6.1.5.5.7.3.4";
	private static final String EKU_CODE_SIGN_OID = "1.3.6.1.5.5.7.3.3";
	private static final String EKU_CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";
	private static final String EKU_SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1";
	private static final String UPN = "1.3.6.1.4.1.311.20.2.3";
	private static final String PROFESSIONAL_OID = "2.16.76.1.4.";
	private static final String OAB_OID = "2.16.76.1.4.2.1.1";
	private static final String PJ_PF_INSS_OID = "2.16.76.1.3.7";
	private static final String PERSON_NAME_OID = "2.16.76.1.3.2";
	private static final String PF_PF_INSS_OID = "2.16.76.1.3.6";
	private static final String ELEITOR_OID = "2.16.76.1.3.5";
	private static final String PJ_PF_ID = "2.16.76.1.3.4";

	// PF 2.16.76.1.3.5 - Titulo de eleitor(12), Zona Eleitoral (3), Seção (4)
	private static final int ELEITOR_INI = 0;
	private static final int ELEITOR_LEN = 12;
	private static final int ZONA_INI = ELEITOR_LEN;
	private static final int ZONA_LEN = 3;
	private static final int SECAO_INI = ZONA_INI + ZONA_LEN;
	private static final int SECAO_LEN = 4;

	// PJ 2.16.76.1.3.7 - INSS (12)
	private static final int INSS_INI = 0;
	private static final int INSS_LEN = 12;

	// 2.16.76.1.4.2.1.1- = nas primeiras 07 (sete) posições os dígitos
	// alfanuméricos do Número de Inscrição junto a Seccional, e nas 2 (duas)
	// posições subseqüentes a sigla do Estado da Seccional.–
	private static final int OAB_REG_INI = 0;
	private static final int OAB_REG_LEN = 12;
	private static final int OAB_UF_INI = OAB_REG_LEN;
	private static final int OAB_UF_LEN = 3;

	public byte[] buildCmsBody(String signedHashId,
			X509Certificate certContent, byte[] content, String hashId,
			int version) throws CertificateEncodingException, IOException {
		final DEREncodableVector whole = new DEREncodableVector();
		whole.add(new DERObjectIdentifier(CMS_SIGNED_ID));

		final DEREncodableVector body = new DEREncodableVector();
		// ----- versao -------
		// final int version = 1;
		body.add(new DERInteger(version));
		buildDigestAlg(body, hashId);
		// buildContentInfo(body, content);
		buildCerts(body, certContent);

		buildSignerInfo(body, signedHashId, certContent, hashId);

		whole.add(new DERTaggedObject(0, new DERSequence(body)));

		return genOutput(new DERSequence(whole));

	}

	public byte[] buildCmsBody(byte[] signedHashId,
			X509Certificate certContent, List<X509Certificate> chain,
			int hashId, int version, int attachSize) throws Exception {
		final DEREncodableVector whole = new DEREncodableVector(); // 0 SEQ
		whole.add(new DERObjectIdentifier(CMS_SIGNED_ID)); // 1 SEQ

		final DEREncodableVector body = new DEREncodableVector();
		// ----- versao -------
		// final int version = 1;
		body.add(new DERInteger(version)); // 3 INT
		buildDigestAlg(body, getHashAlg(hashId)); // 3 SET
		buildContentInfo(body, attachSize); // 3 SEQ
		buildCerts(body, chain); // 3 CS

		buildSignerInfo(body, signedHashId, certContent, hashId); // 3 SET

		whole.add(new DERTaggedObject(0, new DERSequence( // 2 SEQ
				body))); // 1 CS

		return genOutput(new DERSequence(whole));

	}

	// cmsOut = de.buildADRBBody(asiEx.getSignedHash(), asiEx.getX509(),
	// addChain?chain:null,
	// asiEx.getOrigHash(),
	// policyHash, asiEx.getCertHash(), asiEx.getSigningTime(),
	// asiEx.getIdSha(), policyUri, policyId,
	// version, signingCertFallback);

	public byte[] buildADRBBody(List<AppSignedInfoEx> listAsiEx,
			SignPolicy signPol, List<X509Certificate> chain, int version,
			boolean signingCertFallback, int attachSize) throws Exception {
		// AppSignedInfoEx asiEx = listAsiEx.get(0);
		final DEREncodableVector whole = new DEREncodableVector(); // 0 SEQ
		whole.add(new DERObjectIdentifier(CMS_SIGNED_ID)); // 1 SEQ

		final DEREncodableVector body = new DEREncodableVector();
		// ----- versao -------
		// final int version = 1;
		body.add(new DERInteger(version)); // 3 INT

		List<String> listHashId = createHashList(listAsiEx);
		buildDigestAlg(body, listHashId); // 3 SET

		buildContentInfo(body, attachSize); // 3 SEQ
		if (chain != null) {
			buildCerts(body, chain); // 3 CS
		} else {
			buildCertsASIE(body, listAsiEx); // 3 CS
		}

		// buildADRBSignerInfo(body, asiEx.getSignedHash(), asiEx.getX509(),
		// asiEx.getOrigHash(), signPol.getPolicyHash(),
		// asiEx.getCertHash(), asiEx.getSigningTime(),
		// asiEx.getIdSha(), signPol.getPolicyUri(),
		// signPol.getPolicyId(),
		// signingCertFallback); // 3 SET

		buildADRBSignerInfo(body, listAsiEx, signPol, signingCertFallback); // 3
																			// SET

		whole.add(new DERTaggedObject(0, new DERSequence( // 2 SEQ
				body))); // 1 CS

		return genOutput(new DERSequence(whole));

	}

	private List<String> createHashList(List<AppSignedInfoEx> listAsiEx)
			throws Exception {
		List<String> ret = new ArrayList<String>();

		for (AppSignedInfoEx next : listAsiEx) {
			ret.add(getHashAlg(next.getIdSha()));
		}

		dedup(ret);

		return ret;
	}

	private void dedup(List<String> list) {
		Map<String, String> map = new HashMap<String, String>();
		Iterator<String> it = list.iterator();

		while (it.hasNext()) {
			String next = it.next();
			map.put(next, next);
		}

		list.clear();
		for (String next : map.values()) {
			list.add(next);
		}

	}

	private byte[] genOutput(DERSequence whole) throws IOException {
		final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		final ASN1OutputStream dout = new ASN1OutputStream(bOut);
		dout.writeObject(whole);
		dout.close();

		return bOut.toByteArray();
	}

	private void buildSignerInfo(DEREncodableVector body,
			byte[] signedHashContent, X509Certificate certContent, int hashId)
			throws Exception {
		// ----- Signers Info --------

		final DEREncodableVector vec = new DEREncodableVector();
		final DEREncodableVector signerinfoVector = new DEREncodableVector();
		signerinfoVector.add(new DERInteger(SI_VERSION));

		signerinfoVector.add(siAddCert(certContent));
		signerinfoVector.add(siAddDigestAlgorithm(getHashAlg(hashId)));
		signerinfoVector
				.add(siAddDigestEncryptionAlgorithm(getHashSignAlg(hashId)));
		// Add the digest
		signerinfoVector.add(new DEROctetString(signedHashContent));

		final DERSequence siSeq = new DERSequence(signerinfoVector);
		vec.add(siSeq);
		DERSet siSet = new DERSet(vec);
		body.add(siSet);

	}

	private void buildADRBSignerInfo(DEREncodableVector body,
			List<AppSignedInfoEx> listAsiEx, SignPolicy signPol,
			boolean signingCertFallback) throws Exception {
		final DEREncodableVector vec = new DEREncodableVector();
		// DERSequence siSeq = null;

		// ----- Signers Info --------
		for (AppSignedInfoEx next : listAsiEx) {
			final DEREncodableVector signerinfoVector = new DEREncodableVector();
			String hashId = getHashAlg(next.getIdSha());
			String hashSignId = getHashSignAlg(next.getIdSha());

			signerinfoVector.add(new DERInteger(SI_VERSION));

			signerinfoVector.add(siAddCert(next.getX509()));
			signerinfoVector.add(siAddDigestAlgorithm(hashId));
			// der encoded structure
			DERTaggedObject derEncStruct = adrbSiCreateDerEncSigned(
					next.getOrigHash(), signPol.getPolicyHash(),
					next.getCertHash(), next.getX509(), next.getSigningTime(),
					next.getIdSha(), signPol.getPolicyUri(),
					signPol.getPolicyId(), signingCertFallback);
			signerinfoVector.add(derEncStruct);

			signerinfoVector.add(siAddDigestEncryptionAlgorithm(hashSignId));
			// Add the digest
			signerinfoVector.add(new DEROctetString(next.getSignedHash()));

			final DERSequence siSeq = new DERSequence(signerinfoVector);
			vec.add(siSeq);
		}
		// ----- Signers Info --------

		DERSet siSet = new DERSet(vec);
		body.add(siSet);

	}

	// private void buildADRBSignerInfo(DEREncodableVector body,
	// byte[] signedHashContent, X509Certificate certContent,
	// byte[] origHash, byte[] polHash, byte[] certHash, Date now,
	// int hashOption, String sigPolicyUri, String sigPolicyId,
	// boolean signingCertFallback) throws Exception {
	// String hashId = getHashAlg(hashOption);
	// String hashSignId = getHashSignAlg(hashOption);
	// // ----- Signers Info --------
	//
	// final DEREncodableVector vec = new DEREncodableVector();
	// final DEREncodableVector signerinfoVector = new DEREncodableVector();
	// signerinfoVector.add(new DERInteger(SI_VERSION));
	//
	// signerinfoVector.add(siAddCert(certContent));
	// signerinfoVector.add(siAddDigestAlgorithm(hashId));
	// // der encoded structure
	// DERTaggedObject derEncStruct = adrbSiCreateDerEncSigned(origHash,
	// polHash, certHash, certContent, now, hashOption, sigPolicyUri,
	// sigPolicyId, signingCertFallback);
	// signerinfoVector.add(derEncStruct);
	//
	// signerinfoVector.add(siAddDigestEncryptionAlgorithm(hashSignId));
	// // Add the digest
	// signerinfoVector.add(new DEROctetString(signedHashContent));
	//
	// final DERSequence siSeq = new DERSequence(signerinfoVector);
	// vec.add(siSeq);
	// DERSet siSet = new DERSet(vec);
	// body.add(siSet);
	//
	// }

	public DERTaggedObject adrbSiCreateDerEncSigned(byte[] origHash,
			byte[] polHash, byte[] certHash, X509Certificate cert, Date now,
			int hashId, String sigPolicyUri, String sigPolicyId,
			boolean signingCertFallback) throws Exception {

		DERSequence seq00 = siCreateDerEncSeqADRB(origHash, polHash, certHash,
				cert, now, hashId, sigPolicyUri, sigPolicyId,
				signingCertFallback);

		DERTaggedObject derEncStruct = new DERTaggedObject(false, 0, seq00);
		return derEncStruct;
	}

	public ASN1Set siCreateDerEncSignedADRB(byte[] origHash, byte[] polHash,
			byte[] certHash, X509Certificate cert, Date now, int hashId,
			String sigPolicyUri, String sigPolicyId, boolean signingCertFallback)
			throws Exception {

		DERSequence seq00 = siCreateDerEncSeqADRB(origHash, polHash, certHash,
				cert, now, hashId, sigPolicyUri, sigPolicyId,
				signingCertFallback);

		ASN1Set retSet = new DERSet(seq00);
		return retSet;
	}

	public ASN1Set siCreateDerEncSignedCMS3(byte[] origHash, byte[] certHash,
			X509Certificate cert, Date now, String hashId)
			throws CertificateEncodingException {
		return null;

	}

	private DERSequence siCreateDerEncSeqADRB(byte[] origHash, byte[] polHash,
			byte[] certHash, X509Certificate cert, Date now, int hashNdx,
			String sigPolicyUri, String sigPolicyId, boolean signingCertFallback)
			throws Exception {
		String hashId = getHashAlg(hashNdx);
		final DEREncodableVector desSeq = new DEREncodableVector();

		// As assinaturas feitas segundo esta PA definem como obrigatórios as
		// seguintes atributos
		// assinados:
		// a) id-contentType;
		// b) id-messageDigest;
		// c.1) Para as versões 1.0, 1.1 e 2.0, id-aa-signingCertificate;
		// c.2) A partir da versão 2.1, inclusive, id-aa-signingCertificateV2;
		// d) id-aa-ets-sigPolicyId.

		// OPTIONAL
		// private static final String ID_SIGNING_TIME = "1.2.840.113549.1.9.5";
		if (now != null) {
			Attribute seq3 = createSigningTime(now);
			desSeq.add(seq3);
		}

		// D
		// private static final String ID_SIG_POLICY =
		// "1.2.840.113549.1.9.16.2.15";

		if (polHash != null && sigPolicyUri != null && sigPolicyId != null) {
			Attribute seq2 = createPolicyId(polHash, hashId, sigPolicyUri,
					sigPolicyId);
			desSeq.add(seq2);
		}

		// C
		// private static final String ID_SIGNING_CERT2 =
		// "1.2.840.113549.1.9.16.2.47";
		if (certHash != null && cert != null) {
			Attribute seq1 = createCertRef(certHash, cert, signingCertFallback,
					hashNdx);
			desSeq.add(seq1);
		}

		// B
		// private static final String ID_MESSAGE_DIGEST =
		// "1.2.840.113549.1.9.4";
		if (origHash != null) {
			Attribute seq4 = createMessageDigest(origHash);
			desSeq.add(seq4);
		}

		// A
		// private static final String ID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
		Attribute seq5 = createContentType();
		desSeq.add(seq5);

		DERSequence seq00 = new DERSequence(desSeq);
		return seq00;
	}

	private Attribute createContentType() {
		// // final DEREncodableVector desSeq = new DEREncodableVector();
		// // desSeq.add(new DERObjectIdentifier(ID_CONTENT_TYPE));
		final DEREncodableVector setEV = new DEREncodableVector();
		setEV.add(new DERObjectIdentifier(ID_PKCS7_DATA));

		DERSet set = new DERSet(setEV);
		// // desSeq.add(set);
		// // DERSequence seq = new DERSequence(desSeq);
		Attribute seq1 = new Attribute(
				new DERObjectIdentifier(ID_CONTENT_TYPE), set);
		return seq1;
	}

	private Attribute createMessageDigest(byte[] origHash) {
		final DEREncodableVector setEV = new DEREncodableVector();
		setEV.add(new DEROctetString(origHash));

		DERSet set = new DERSet(setEV);

		Attribute seq1 = new Attribute(new DERObjectIdentifier(
				ID_MESSAGE_DIGEST), set);
		return seq1;
	}

	private Attribute createSigningTime(Date now) {
		final DEREncodableVector setEV = new DEREncodableVector();
		setEV.add(new DERUTCTime(now));

		DERSet set = new DERSet(setEV);
		Attribute seq1 = new Attribute(
				new DERObjectIdentifier(ID_SIGNING_TIME), set);
		return seq1;
	}

	private Attribute createPolicyId(byte[] polHash, String polHashAlg,
			String sigPolicyUri, String sigPolicyId) {

		final DEREncodableVector desSeq12 = new DEREncodableVector();
		desSeq12.add(new DERObjectIdentifier(polHashAlg));
		DERSequence seq12 = new DERSequence(desSeq12);

		final DEREncodableVector desSeq1 = new DEREncodableVector();
		desSeq1.add(seq12);
		desSeq1.add(new DEROctetString(polHash));
		DERSequence seq1 = new DERSequence(desSeq1);

		// // end seq 1

		// IGUALAR AO ITAU

		final DEREncodableVector desSeq22 = new DEREncodableVector();
		desSeq22.add(new DERObjectIdentifier(ID_SIG_POLICY_URI));
		desSeq22.add(new DERIA5String(sigPolicyUri));
		DERSequence seq22 = new DERSequence(desSeq22);

		final DEREncodableVector desSeq2 = new DEREncodableVector();
		desSeq2.add(seq22);

		DERSequence seq2 = new DERSequence(desSeq2);

		final DEREncodableVector aevDSet1 = new DEREncodableVector();
		final DEREncodableVector aevDSeq1 = new DEREncodableVector();
		aevDSeq1.add(new DERObjectIdentifier(sigPolicyId));
		aevDSeq1.add(seq1);

		aevDSeq1.add(seq2);

		DERSequence dsq1 = new DERSequence(aevDSeq1);
		aevDSet1.add(dsq1);
		DERSet ds1 = new DERSet(aevDSet1);

		Attribute ret = new Attribute(new DERObjectIdentifier(ID_SIG_POLICY),
				ds1);
		return ret;
	}

	private Attribute createCertRef(byte[] certHash,
			X509Certificate certContent, boolean signingCertFallback, int hashId)
			throws Exception {
		// *** BEGIN ***

		// 5.2.1.1.3 Certificados Obrigatoriamente Referenciados
		// O atributo signingCertificate deve conter referência apenas ao
		// certificado do signatário.

		// 5.2.1.1.4 Certificados Obrigatórios do Caminho de Certificação
		// Para a versão 1.0: nenhum certificado
		// Para as versões 1.1, 2.0 e 2.1: o certificado do signatário.

		// ESSCertIDv2 ::= SEQUENCE {
		// hashAlgorithm AlgorithmIdentifier
		// DEFAULT {algorithm id-sha256},
		// certHash Hash,
		// issuerSerial IssuerSerial OPTIONAL
		// }
		//
		// Hash ::= OCTET STRING
		//
		// IssuerSerial ::= SEQUENCE {
		// issuer GeneralNames,
		// serialNumber CertificateSerialNumber
		// }
		final DEREncodableVector issuerSerialaev = new DEREncodableVector();

		final DEREncodableVector issuerCertaev = new DEREncodableVector();

		DERTaggedObject issuerName = new DERTaggedObject(true, 4, // issuer
																	// GeneralNames,
				getEncodedIssuer(certContent.getTBSCertificate()));

		// DERTaggedObject issuerName = new DERTaggedObject(false, 0, // issuer
		// GeneralNames,
		// getEncodedIssuer(certContent.getTBSCertificate()));
		issuerCertaev.add(issuerName);

		DERSequence issuerCertseq = new DERSequence(issuerCertaev); // IssuerSerial
																	// ::=
																	// SEQUENCE
																	// {
		issuerSerialaev.add(issuerCertseq);

		// serialNumber CertificateSerialNumber
		BigInteger serialNumber = certContent.getSerialNumber();
		issuerSerialaev.add(new DERInteger(serialNumber));

		DERSequence issuerSerial = new DERSequence(issuerSerialaev);
		// *** END ***

		final DEREncodableVector essCertIDv2aev = new DEREncodableVector();
		essCertIDv2aev.add(new DEROctetString(certHash)); // Hash ::= OCTET
															// STRING

		essCertIDv2aev.add(issuerSerial); // ESSCertIDv2 ::= SEQUENCE {

		// hashAlgorithm AlgorithmIdentifier

		if (!((signingCertFallback && hashId == NDX_SHA1) || (!signingCertFallback && hashId == NDX_SHA256))) {
			DERObjectIdentifier hashAlgorithm = new DERObjectIdentifier(
					getHashAlg(hashId));
			essCertIDv2aev.add(hashAlgorithm);
		}
		// Nota 4: Para o atributo ESSCertIDv2, utilizada nas versões 2.1 das
		// políticas de assinatura
		// baseadas em CAdES, as aplicações NÃO DEVEM codificar o campo
		// “hashAlgorithm” caso
		// utilize o mesmo algoritmo definido como valor default (SHA-256),
		// conforme ISO 8825-1.

		DERSequence essCertIDv2seq = new DERSequence(essCertIDv2aev);

		// ************************************************************************
		//
		final DEREncodableVector aevSeq3 = new DEREncodableVector();
		aevSeq3.add(essCertIDv2seq);
		DERSequence seq3 = new DERSequence(aevSeq3);

		final DEREncodableVector aevSeq2 = new DEREncodableVector();
		aevSeq2.add(seq3);
		DERSequence seq2 = new DERSequence(aevSeq2);

		final DEREncodableVector aevSet = new DEREncodableVector();
		aevSet.add(seq2);
		ASN1Set mainSet = new DERSet(aevSet);

		Attribute seq1 = new Attribute(new DERObjectIdentifier(
				signingCertFallback ? ID_SIGNING_CERT : ID_SIGNING_CERT2),
				mainSet);
		return seq1;
	}

	private void buildSignerInfo(DEREncodableVector body,
			String signedHashContent, X509Certificate certContent, String hashId)
			throws CertificateEncodingException {
		// ----- Signers Info --------

		final DEREncodableVector vec = new DEREncodableVector();
		final DEREncodableVector signerinfoVector = new DEREncodableVector();
		signerinfoVector.add(new DERInteger(SI_VERSION)); // 5 INT

		signerinfoVector.add(siAddCert(certContent));
		signerinfoVector.add(siAddDigestAlgorithm(hashId));
		signerinfoVector.add(siAddDigestEncryptionAlgorithm(ID_SHA1_RSA)); // 6
																			// OCT
																			// STR
		// Add the digest
		signerinfoVector.add(new DEROctetString(
				getDerSignedDigest(signedHashContent)));

		final DERSequence siSeq = new DERSequence(signerinfoVector); // 4 SEQ
		vec.add(siSeq);
		DERSet siSet = new DERSet(vec); // 3 SET
		body.add(siSet);

	}

	private byte[] getDerSignedDigest(String signedHashContent) {

		byte[] ret = Base64.decode(signedHashContent);
		return ret;
	}

	private DERSequence siAddDigestEncryptionAlgorithm(String hashId) {

		// Nota 3: Em atenção à RFC 3370 (Cryptographic Message Syntax (CMS)
		// Algorithms), item
		// "2.1 SHA-1"; e RFC 5754 (Using SHA2 Algorithms with Cryptographic
		// Message Syntax),
		// item "2 - Message Digest Algorithms", recomenda-se a ausência do
		// campo "parameters" na
		// estrutura "AlgorithmIdentifier", usada na indicação do algoritmo de
		// hash, presentes nas
		// estruturas ASN.1 "SignedData.digestAlgorithms",
		// "SignerInfo.digestAlgorithm" e
		// "SignaturePolicyId.sigPolicyHash.hashAlgorithm".
		// AlgorithmIdentifier ::= SEQUENCE {
		// algorithm OBJECT IDENTIFIER,
		// parameters ANY DEFINED BY algorithm OPTIONAL }

		// Os processos para criação e verificação de assinaturas segundo esta
		// PA devem utilizar o
		// algoritmo :
		// a) para a versão 1.0: sha1withRSAEncryption(1 2 840 113549 1 1 5),
		// b) para a versão 1.1: sha1withRSAEncryption(1 2 840 113549 1 1 5) ou
		// sha256WithRSAEncryption(1.2.840.113549.1.1.11)
		// c) para as versões 2.0 e 2.1:
		// sha256WithRSAEncryption(1.2.840.113549.1.1.11).

		DEREncodableVector digestEncVetor = new DEREncodableVector();
		digestEncVetor.add(new DERObjectIdentifier(hashId));
		// VER NOTA
		// digestEncVetor.add(new DERNull());
		return new DERSequence(digestEncVetor);
	}

	private DERSequence siAddDigestAlgorithm(String hashId) {
		// Add the digestEncAlgorithm
		DEREncodableVector digestVetor = new DEREncodableVector();
		digestVetor.add(new DERObjectIdentifier(hashId)); // 6 OID
		digestVetor.add(new DERNull()); // 6 NULL
		return new DERSequence(digestVetor); // 5 SEQ
	}

	private DERSequence siAddCert(X509Certificate certContent)
			throws CertificateEncodingException {
		DEREncodableVector certVetor = new DEREncodableVector();
		certVetor.add(getEncodedIssuer(certContent.getTBSCertificate())); // 6
																			// ISSUER
		certVetor.add(new DERInteger(certContent.getSerialNumber())); // 6 INT -
																		// SERIAL
		return (new DERSequence(certVetor)); // 5 SEQ

	}

	private static ASN1Sequence getEncodedIssuer(final byte[] enc) {
		try {
			final ASN1InputStream in = new ASN1InputStream(
					new ByteArrayInputStream(enc));
			final ASN1Sequence seq = (ASN1Sequence) in.readObject();
			return (ASN1Sequence) seq
					.getObjectAt(seq.getObjectAt(0) instanceof DERTaggedObject ? 3
							: 2);
		} catch (final IOException e) {
			return null;
		}
	}

	private void buildCertsASIE(DEREncodableVector body,
			List<AppSignedInfoEx> listAsiEx)
			throws CertificateEncodingException, IOException {
		List<X509Certificate> chain = new ArrayList<X509Certificate>();
		for (AppSignedInfoEx next : listAsiEx) {
			chain.add(next.getX509());
		}
		buildCerts(body, chain);

	}

	private void buildCerts(DEREncodableVector body, List<X509Certificate> chain)
			throws IOException, CertificateEncodingException {
		// -------- Certificados
		DEREncodableVector certVector = new DEREncodableVector();
		for (X509Certificate next : chain) {

			ASN1InputStream tempstream = new ASN1InputStream(
					new ByteArrayInputStream(next.getEncoded()));
			certVector.add(tempstream.readObject()); // 5 CERT (SEQ)
		}

		final DERSet dercertificates = new DERSet(certVector); // 4 SET
		body.add(new DERTaggedObject(false, 0, dercertificates)); // 3 CS
	}

	private void buildCerts(DEREncodableVector body, X509Certificate certContent)
			throws IOException, CertificateEncodingException {
		// -------- Certificados
		DEREncodableVector certVector = new DEREncodableVector();
		ASN1InputStream tempstream = new ASN1InputStream(
				new ByteArrayInputStream(certContent.getEncoded()));
		certVector.add(tempstream.readObject()); // 5 CERT (SEQ)
		final DERSet dercertificates = new DERSet(certVector); // 4 SET
		body.add(new DERTaggedObject(false, 0, dercertificates)); // 3 CS
	}

	private void buildContentInfo(final DEREncodableVector body, int size) {

		// ------ Content Info
		DEREncodableVector contentInfoVector = new DEREncodableVector();
		contentInfoVector.add(new DERObjectIdentifier(ID_PKCS7_DATA)); // 4 OID
		if (size != DETACHED) {
			byte[] content = new byte[size];
			for (int i = 0; i < size; i++) {
				content[i] = (byte) 0xba;
			}
			contentInfoVector.add(new DERTaggedObject(0, new DEROctetString(
					content)));
		}
		// CONTENT INFO

		final DERSequence contentinfo = new DERSequence(contentInfoVector); // 3
																			// SEQ
		body.add(contentinfo);

	}

	private void buildDigestAlg(final DEREncodableVector body, String hashId) {
		// ---------- algoritmos de digest
		final DEREncodableVector algos = new DEREncodableVector();
		algos.add(new DERObjectIdentifier(hashId)); // 4 OID
		algos.add(new DERNull()); // 4 NULL
		final DEREncodableVector algoSet = new DEREncodableVector();
		algoSet.add(new DERSequence(algos));
		final DERSet digestAlgorithms = new DERSet(algoSet); // 2
		// SET
		body.add(digestAlgorithms);
	}

	private void buildDigestAlg(final DEREncodableVector body,
			List<String> listHashId) {
		// ---------- algoritmos de digest
		final DEREncodableVector algos = new DEREncodableVector();
		for (String next : listHashId) {
			algos.add(new DERObjectIdentifier(next)); // 4 OID
			algos.add(new DERNull()); // 4 NULL
		}

		final DEREncodableVector algoSet = new DEREncodableVector();

		algoSet.add(new DERSequence(algos));
		final DERSet digestAlgorithms = new DERSet(algoSet); // 2
		// SET
		body.add(digestAlgorithms);
	}

	public static String getHashAlg(int hash) throws Exception {
		String ret = "";
		switch (hash) {
		case NDX_SHA1:
			ret = ID_SHA1;
			break;

		case NDX_SHA224:
			ret = ID_SHA1;
			break;

		case NDX_SHA256:
			ret = ID_SHA256;
			break;

		case NDX_SHA384:
			ret = ID_SHA384;
			break;

		case NDX_SHA512:
			ret = ID_SHA512;
			break;

		default:
			LOG.error("unidentified hash alg " + hash);
			throw new Exception("unidentified  hash alg " + hash);

		}
		return ret;
	}

	private String getHashSignAlg(int hash) throws Exception {
		String ret = "";
		switch (hash) {
		case NDX_SHA1:
			ret = ID_SHA1_RSA;
			break;

		case NDX_SHA224:
			ret = ID_SHA1_RSA;
			break;

		case NDX_SHA256:
			ret = ID_SHA256_RSA;
			break;

		case NDX_SHA384:
			ret = ID_SHA384_RSA;
			break;

		case NDX_SHA512:
			ret = ID_SHA512_RSA;
			break;

		default:
			LOG.error("unidentified hash alg " + hash);
			throw new Exception("unidentified hash alg " + hash);
			// break;
		}
		return ret;
	}

	// capicom service

	public static String extractHashId(byte[] sign) throws Exception {
		String ret = null;
		ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(sign));
		DERObject topLevel = is.readObject();
		LOG.debug("top level:" + topLevel.getClass().getName());

		if (topLevel instanceof org.bouncycastle.asn1.ASN1Sequence) {
			ASN1Sequence topLevelDLS = (ASN1Sequence) topLevel;
			if (topLevelDLS.size() == 2) {
				DEREncodable level1 = topLevelDLS.getObjectAt(1);
				LOG.debug("level1:" + level1.getClass().getName());
				if (level1 instanceof org.bouncycastle.asn1.DERTaggedObject) {
					DERTaggedObject level1TO = (DERTaggedObject) level1;
					DERObject level2 = level1TO.getObject();
					LOG.debug("level2:" + level2.getClass().getName());
					if (level2 instanceof org.bouncycastle.asn1.DERSequence) {
						DERSequence level2DS = (DERSequence) level2;
						LOG.debug("level2 len:" + level2DS.size());

						DEREncodable level3_1 = level2DS.getObjectAt(1);
						LOG.debug("level3_1:" + level3_1.getClass().getName());

						if (level3_1 instanceof org.bouncycastle.asn1.DERSet) {
							DERSet level3_1Set = (DERSet) level3_1;
							DEREncodable level4_1 = level3_1Set.getObjectAt(0);
							LOG.debug("level4_1:"
									+ level4_1.getClass().getName());

							if (level4_1 instanceof org.bouncycastle.asn1.DERSequence) {
								DERSequence level4_1Seq = (DERSequence) level4_1;
								DEREncodable level5_0 = level4_1Seq
										.getObjectAt(0);

								LOG.debug("level5_0:"
										+ level5_0.getClass().getName());

								if (level5_0 instanceof DERObjectIdentifier) {
									DERObjectIdentifier level5_0Seq = (DERObjectIdentifier) level5_0;
									LOG.debug(level5_0Seq.toString());
									ret = level5_0Seq.toString();

								} else {
									LOG.error("DER enconding error");
									throw new Exception("DER enconding error");
								}

							} else {
								LOG.error("DER enconding error");
								throw new Exception("DER enconding error");
							}

						} else {
							LOG.error("DER enconding error");
							throw new Exception("DER enconding error");
						}

					} else {
						LOG.error("DER enconding error");
						throw new Exception("DER enconding error");
					}

				} else {
					LOG.error("DER enconding error");
					throw new Exception("DER enconding error");
				}
			} else {
				LOG.error("DER enconding error");
				throw new Exception("DER enconding error");
			}

		} else {
			LOG.error("DER enconding error");
			throw new Exception("DER enconding error");
		}

		return ret;
	}

	public static byte[] extractSignature(byte[] sign) throws Exception {
		byte[] ret = null;
		ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(sign));
		DERObject topLevel = is.readObject();
		LOG.debug("top level:" + topLevel.getClass().getName());

		if (topLevel instanceof org.bouncycastle.asn1.ASN1Sequence) {
			ASN1Sequence topLevelDLS = (ASN1Sequence) topLevel;
			if (topLevelDLS.size() == 2) {
				DEREncodable level1 = topLevelDLS.getObjectAt(1);
				LOG.debug("level1:" + level1.getClass().getName());
				if (level1 instanceof org.bouncycastle.asn1.DERTaggedObject) {
					DERTaggedObject level1TO = (DERTaggedObject) level1;
					DERObject level2 = level1TO.getObject();
					LOG.debug("level2:" + level2.getClass().getName());
					if (level2 instanceof org.bouncycastle.asn1.DERSequence) {
						DERSequence level2DS = (DERSequence) level2;
						LOG.debug("level2 len:" + level2DS.size());
						DEREncodable level3_4 = level2DS.getObjectAt(level2DS
								.size() - 1);
						LOG.debug("level3_4:" + level3_4.getClass().getName());
						if (level3_4 instanceof org.bouncycastle.asn1.DERSet) {
							DERSet level3_4DS = (DERSet) level3_4;
							DEREncodable level3_4_0 = level3_4DS.getObjectAt(0);
							LOG.debug("level3_4_0:"
									+ level3_4_0.getClass().getName());
							if (level3_4_0 instanceof org.bouncycastle.asn1.DERSequence) {
								DERSequence level3_4_0DS = (DERSequence) level3_4_0;
								LOG.debug("level3_4_0DS len:"
										+ level3_4_0DS.size());
								DEREncodable signature = level3_4_0DS
										.getObjectAt(level3_4_0DS.size() - 1);
								LOG.debug("signature:"
										+ signature.getClass().getName());
								if (signature instanceof org.bouncycastle.asn1.DEROctetString) {
									DEROctetString signDOS = (DEROctetString) signature;
									ret = signDOS.getOctets();
								}
							} else {
								LOG.error("DER enconding error");
								throw new Exception("DER enconding error");
							}

						} else {
							LOG.error("DER enconding error");
							throw new Exception("DER enconding error");
						}
					} else {
						LOG.error("DER enconding error");
						throw new Exception("DER enconding error");
					}

				} else {
					LOG.error("DER enconding error");
					throw new Exception("DER enconding error");
				}
			} else {
				LOG.error("DER enconding error");
				throw new Exception("DER enconding error");
			}

		} else {
			LOG.error("DER enconding error");
			throw new Exception("DER enconding error");
		}

		return ret;
	}

	public static DERTaggedObject extractDTOSignPolicyOid(byte[] sign,
			SignCompare signCompare) throws Exception {
		DERTaggedObject ret = null;
		ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(sign));
		DERObject topLevel = is.readObject();
		LOG.debug("top level:" + topLevel.getClass().getName());

		if (topLevel instanceof org.bouncycastle.asn1.ASN1Sequence) {
			ASN1Sequence topLevelDLS = (ASN1Sequence) topLevel;
			if (topLevelDLS.size() == 2) {
				DEREncodable level1 = topLevelDLS.getObjectAt(1);
				LOG.debug("level1:" + level1.getClass().getName());
				if (level1 instanceof org.bouncycastle.asn1.DERTaggedObject) {
					DERTaggedObject level1TO = (DERTaggedObject) level1;
					DERObject level2 = level1TO.getObject();
					LOG.debug("level2:" + level2.getClass().getName());
					if (level2 instanceof org.bouncycastle.asn1.DERSequence) {
						DERSequence level2DS = (DERSequence) level2;
						LOG.debug("level2 len:" + level2DS.size());
						signCompare.setNumCerts(extractCertCount(level2DS));
						ret = extractSignedAttributes(level2DS);
					} else {
						LOG.error("DER enconding error");
						throw new Exception("DER enconding error");
					}

				} else {
					LOG.error("DER enconding error");
					throw new Exception("DER enconding error");
				}
			} else {
				LOG.error("DER enconding error");
				throw new Exception("DER enconding error");
			}

		} else {
			LOG.error("DER enconding error");
			throw new Exception("DER enconding error");
		}

		return ret;
	}

	public static List<byte[]> extractCertList(byte[] sign) throws Exception {
		List<byte[]> ret = null;
		ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(sign));
		DERObject topLevel = is.readObject();
		LOG.debug("top level:" + topLevel.getClass().getName());

		if (topLevel instanceof org.bouncycastle.asn1.ASN1Sequence) {
			ASN1Sequence topLevelDLS = (ASN1Sequence) topLevel;
			if (topLevelDLS.size() == 2) {
				DEREncodable level1 = topLevelDLS.getObjectAt(1);
				LOG.debug("level1:" + level1.getClass().getName());
				if (level1 instanceof org.bouncycastle.asn1.DERTaggedObject) {
					DERTaggedObject level1TO = (DERTaggedObject) level1;
					DERObject level2 = level1TO.getObject();
					LOG.debug("level2:" + level2.getClass().getName());
					if (level2 instanceof org.bouncycastle.asn1.DERSequence) {
						DERSequence level2DS = (DERSequence) level2;
						LOG.debug("level2 len:" + level2DS.size());
						ret = extractCertArray(level2DS);
					} else {
						LOG.error("DER enconding error");
						throw new Exception("DER enconding error");
					}

				} else {
					LOG.error("DER enconding error");
					throw new Exception("DER enconding error");
				}
			} else {
				LOG.error("DER enconding error");
				throw new Exception("DER enconding error");
			}

		} else {
			LOG.error("DER enconding error");
			throw new Exception("DER enconding error");
		}

		return ret;
	}

	public static int extractCertCount(DERSequence certTree) {
		DEREncodable level0 = getAt(certTree, 3);
		if (level0 instanceof DERTaggedObject) {
			DERTaggedObject level0Tag = (DERTaggedObject) level0;
			DEREncodable level0Obj = level0Tag.getObject();
			if (level0Obj instanceof DERSequence) {
				DERSequence level0Seq = (DERSequence) level0Obj;
				return 1;
			} else if (level0Obj instanceof ASN1Sequence) {
				ASN1Sequence level0Seq = (ASN1Sequence) level0Obj;
				return level0Seq.size();
			}
		}
		return certTree.size();
	}

	public static List<byte[]> extractCertArray(DERSequence certTree) {
		List<byte[]> ret = new ArrayList<byte[]>();

		DEREncodable level0 = getAt(certTree, 3);
		if (level0 instanceof DERTaggedObject) {
			DERTaggedObject level0Tag = (DERTaggedObject) level0;
			DEREncodable level0Obj = level0Tag.getObject();
			if (level0Obj instanceof DERSequence) {
				try {
					DERSequence level0Seq = (DERSequence) level0Obj;
					if (level0Seq.getObjectAt(2) instanceof DERBitString) {
						// achei o certificado
						byte[] b = level0Seq.getEncoded();
						ret.add(b);
					} else {
						for (int i = 0; i < level0Seq.size(); i++) {

							DEREncodable objNdx = level0Seq.getObjectAt(i);
							if (objNdx instanceof DERSequence) {
								try {
									DERSequence objNdx2 = (DERSequence) objNdx;
									byte[] b = objNdx2.getEncoded();
									ret.add(b);
								} catch (IOException e) {
									LOG.error("DER decoding error", e);
								}
							}
						}

					}
				} catch (IOException e) {
					LOG.error("DER decoding error", e);
				}
			} else if (level0Obj instanceof ASN1Sequence) {
				ASN1Sequence level0Seq = (ASN1Sequence) level0Obj;

				for (int i = 0; i < level0Seq.size(); i++) {

					DEREncodable objNdx = level0Seq.getObjectAt(i);
					if (objNdx instanceof DERSequence) {
						try {
							DERSequence objNdx2 = (DERSequence) objNdx;
							byte[] b = objNdx2.getEncoded();
							ret.add(b);
						} catch (IOException e) {
							LOG.error("DER decoding error", e);
						}
					}
				}
			}
		}
		return ret;
	}

	public static DERTaggedObject extractSignedAttributes(DERSequence level2DS)
			throws Exception {
		DERTaggedObject ret = null;

		DEREncodable level3_4 = level2DS.getObjectAt(level2DS.size() - 1);
		LOG.debug("level3_4:" + level3_4.getClass().getName());
		if (level3_4 instanceof org.bouncycastle.asn1.DERSet) {
			DERSet level3_4DS = (DERSet) level3_4;
			DEREncodable level3_4_0 = level3_4DS.getObjectAt(0);
			LOG.debug("level3_4_0:" + level3_4_0.getClass().getName());
			if (level3_4_0 instanceof org.bouncycastle.asn1.DERSequence) {
				DERSequence level3_4_0DS = (DERSequence) level3_4_0;
				LOG.debug("level3_4_0DS len:" + level3_4_0DS.size());
				DEREncodable signedAttribs = level3_4_0DS.getObjectAt(3);
				LOG.debug("signature:" + signedAttribs.getClass().getName());
				if (signedAttribs instanceof org.bouncycastle.asn1.DERTaggedObject) {
					DERTaggedObject signedAttribsDTO = (DERTaggedObject) signedAttribs;
					ret = signedAttribsDTO;

					// trata busca da Policy OID
				} else if (signedAttribs instanceof org.bouncycastle.asn1.DERSequence) {
					ret = null;
				} else {
					LOG.error("DER enconding error");
					throw new Exception("DER enconding error");
				}
			} else {
				LOG.error("DER enconding error");
				throw new Exception("DER enconding error");
			}

		} else {
			LOG.error("DER enconding error");
			throw new Exception("DER enconding error");
		}
		return ret;
	}

	public static void extractSignPolicyRefFromSignedAttrib(
			DERTaggedObject signedAttribsDTO, SignCompare signCompare)
			throws Exception {
		String SignCompare = null;
		DERObject dtoObj = signedAttribsDTO.getObject();
		if (dtoObj instanceof ASN1Sequence) {
			ASN1Sequence topSeq = (ASN1Sequence) dtoObj;
			List<String> signedAttribOid = new ArrayList<String>();
			signCompare.setSignedAttribs(signedAttribOid);
			for (int i = 0; i < topSeq.size(); i++) {
				// treat each SIGNED ATTRIBUTE
				DEREncodable objL1 = topSeq.getObjectAt(i);
				if (objL1 instanceof DERSequence) {
					DERSequence seqL1 = (DERSequence) objL1;
					DEREncodable objL2 = seqL1.getObjectAt(0);
					if (objL2 instanceof DERObjectIdentifier) {
						DERObjectIdentifier saOid = (DERObjectIdentifier) objL2;
						String saOIdStr = saOid.toString();
						// System.out.println(saOIdStr);
						signedAttribOid.add(saOIdStr);

						if (saOIdStr.compareTo(DerEncoder.ID_SIG_POLICY) == 0) {
							DEREncodable objL21 = seqL1.getObjectAt(1);
							if (objL21 instanceof DERSet) {
								DERSet objL21Set = (DERSet) objL21;
								DEREncodable objL3 = objL21Set.getObjectAt(0);
								if (objL3 instanceof DERSequence) {
									DERSequence objL3Seq = (DERSequence) objL3;
									DEREncodable objL4 = objL3Seq
											.getObjectAt(0);
									if (objL4 instanceof DERObjectIdentifier) {
										DERObjectIdentifier objL4Oid = (DERObjectIdentifier) objL4;
										signCompare.setPsOid(objL4Oid
												.toString());
									}
									DEREncodable objL42 = getAt(objL3Seq, 2);
									if (objL42 instanceof DERSequence) {
										DERSequence objL42DerSeq = (DERSequence) objL42;
										DEREncodable objL420 = getAt(
												objL42DerSeq, 0);
										if (objL420 instanceof DERSequence) {
											DERSequence objL420DerSeq = (DERSequence) objL420;
											DEREncodable psUrl = getAt(
													objL420DerSeq, 1);
											if (psUrl instanceof DERIA5String) {
												DERIA5String psUrlIA5 = (DERIA5String) psUrl;
												signCompare.setPsUrl(psUrlIA5
														.getString());
											}
										}
									}

								}
							}
						} else if (saOIdStr
								.compareTo(DerEncoder.ID_SIGNING_TIME) == 0) {
							DEREncodable objL2SetTime = seqL1.getObjectAt(1);
							if (objL2SetTime instanceof DERSet) {
								DERSet objL2SetTimeDer = (DERSet) objL2SetTime;
								DEREncodable objL2SignTime = objL2SetTimeDer
										.getObjectAt(0);
								if (objL2SignTime instanceof DERUTCTime) {
									DERUTCTime objL2SignTimeUTC = (DERUTCTime) objL2SignTime;
									signCompare.setSigningTime(objL2SignTimeUTC
											.getDate());
								}

							}

						}
					}
				}
			}
		}

	}

	public static SignPolicyRef extractVerifyRefence(byte[] policy)
			throws IOException, ParseException {
		SignPolicyRef ret = new SignPolicyRef();

		ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(
				policy));
		DERObject topLevel = is.readObject();
		// SignaturePolicy ::= SEQUENCE {
		// signPolicyHashAlg AlgorithmIdentifier,
		// signPolicyInfo SignPolicyInfo,
		// signPolicyHash SignPolicyHash OPTIONAL }
		if (topLevel instanceof ASN1Sequence) {
			ASN1Sequence topLevelDLS = (ASN1Sequence) topLevel;
			DEREncodable dseqL10 = topLevelDLS.getObjectAt(0);
			if (dseqL10 instanceof ASN1Sequence) {
				ASN1Sequence dseqL10DLS = (ASN1Sequence) dseqL10;
				DEREncodable psHashAlg = dseqL10DLS.getObjectAt(0);
				if (psHashAlg instanceof DERObjectIdentifier) {
					DERObjectIdentifier psHashAlgOid = (DERObjectIdentifier) psHashAlg;
					ret.setPsHashAlg(psHashAlgOid.toString());
				}
			}

			DEREncodable dseqL11 = topLevelDLS.getObjectAt(1);
			if (dseqL11 instanceof ASN1Sequence) {
				// SignPolicyInfo ::= SEQUENCE {
				ASN1Sequence dseqL11DLS = (ASN1Sequence) dseqL11;
				DEREncodable psOid = dseqL11DLS.getObjectAt(0);
				// signPolicyIdentifier SignPolicyId,
				// 2.16.76.1.7.1.6.2.1
				if (psOid instanceof DERObjectIdentifier) {
					DERObjectIdentifier psOidOid = (DERObjectIdentifier) psOid;
					ret.setPsOid(psOidOid.toString());

				}
				DEREncodable dateOfIssue = dseqL11DLS.getObjectAt(1);
				// dateOfIssue GeneralizedTime,
				// 2012-03-22
				if (dateOfIssue instanceof DERGeneralizedTime) {
					DERGeneralizedTime dateOfIssueGT = (DERGeneralizedTime) dateOfIssue;
					ret.setDateOfIssue(dateOfIssueGT.getDate());
				}

				DEREncodable policyIssuerName = dseqL11DLS.getObjectAt(2);
				// policyIssuerName PolicyIssuerName,
				// C=BR, O=ICP-Brasil, OU=Instituto Nacional de Tecnologia da
				// Informacao
				// - ITI
				if (policyIssuerName instanceof ASN1Sequence) {
					ASN1Sequence policyIssuerNameDLSeq = (ASN1Sequence) policyIssuerName;
					DEREncodable policyIssuerName2 = policyIssuerNameDLSeq
							.getObjectAt(0);
					if (policyIssuerName2 instanceof DERTaggedObject) {
						DERTaggedObject policyIssuerName2DTO = (DERTaggedObject) policyIssuerName2;
						DERObject polIssuerNameObj = policyIssuerName2DTO
								.getObject();
						if (polIssuerNameObj instanceof DEROctetString) {
							String polIssuerNameStr = new String(
									((DEROctetString) polIssuerNameObj)
											.getOctets());
							ret.setPolIssuerName(polIssuerNameStr);
						}
					}

				}

				DEREncodable fieldOfApplication = dseqL11DLS.getObjectAt(3);
				// fieldOfApplication FieldOfApplication,
				// Este tipo de assinatura deve ser utilizado em aplicacoes ou
				// processos
				// de negocio nos quais a assinatura digital agrega seguranca a
				// autenticacao de entidades e verificacao de integridade,
				// permitindo
				// sua validacao durante o prazo de, validade dos certificados
				// dos
				// signatarios. Uma vez que nao sao usados carimbos do tempo, a
				// validacao posterior so sera possivel se existirem referencias
				// temporais que identifiquem o momento em que ocorreu a
				// assinatura
				// digital. Nessas situacoes, deve existir legislacao especifica
				// ou um
				// acordo previo entre as partes definindo as referencias a
				// serem
				// utilizadas. Segundo esta PA, e permitido o emprego de
				// multiplas
				// assinaturas.
				if (fieldOfApplication instanceof DEROctetString) {
					DERUTF8String fieldOfApplicationDUS = (DERUTF8String) fieldOfApplication;
					ret.setFieldOfApplication(fieldOfApplicationDUS.getString());
				}
				// signatureValidationPolicy SignatureValidationPolicy,
				// signPolExtensions SignPolExtensions OPTIONAL
				// SignatureValidationPolicy ::= SEQUENCE {
				DEREncodable signatureValidationPolicy = dseqL11DLS
						.getObjectAt(4);
				if (signatureValidationPolicy instanceof ASN1Sequence) {
					ASN1Sequence signatureValidationPolicyDLS = (ASN1Sequence) signatureValidationPolicy;
					// signingPeriod SigningPeriod,
					// NotBefore 2012-03-22
					// NotAfter 2023-06-21
					DEREncodable signingPeriod = signatureValidationPolicyDLS
							.getObjectAt(0);
					if (signingPeriod instanceof ASN1Sequence) {
						ASN1Sequence signingPeriodDLS = (ASN1Sequence) signingPeriod;
						DEREncodable notBefore = signingPeriodDLS
								.getObjectAt(0);
						if (notBefore instanceof DERGeneralizedTime) {
							DERGeneralizedTime notBeforeAGT = (DERGeneralizedTime) notBefore;
							ret.setNotBefore(notBeforeAGT.getDate());

						}

						DEREncodable notAfter = signingPeriodDLS.getObjectAt(1);
						if (notAfter instanceof DERGeneralizedTime) {
							DERGeneralizedTime notAfterAGT = (DERGeneralizedTime) notAfter;
							ret.setNotAfter(notAfterAGT.getDate());
						}

					}

					//
					// commonRules CommonRules,
					DEREncodable commonRules = getAt(
							signatureValidationPolicyDLS, 1);
					if (commonRules instanceof ASN1Sequence) {
						ASN1Sequence commonRulesDLS = (ASN1Sequence) commonRules;
						// CommonRules ::= SEQUENCE {
						// signerAndVeriferRules [0] SignerAndVerifierRules
						// OPTIONAL,
						// signingCertTrustCondition [1]
						// SigningCertTrustCondition OPTIONAL,
						// timeStampTrustCondition [2] TimestampTrustCondition
						// OPTIONAL,
						// attributeTrustCondition [3] AttributeTrustCondition
						// OPTIONAL,
						// algorithmConstraintSet [4] AlgorithmConstraintSet
						// OPTIONAL,
						// signPolExtensions [5] SignPolExtensions OPTIONAL
						// }
						DEREncodable signerAndVeriferRules = getAt(
								commonRulesDLS, 0);

						// SignerAndVerifierRules ::= SEQUENCE {
						// signerRules SignerRules,
						// verifierRules VerifierRules }

						if (signerAndVeriferRules instanceof DERTaggedObject) {
							DERTaggedObject signerAndVeriferRulesDTO = (DERTaggedObject) signerAndVeriferRules;
							DEREncodable signerAndVeriferRulesTmp = signerAndVeriferRulesDTO
									.getObject();
							if (signerAndVeriferRulesTmp instanceof DERSequence) {
								DERSequence signerAndVeriferRulesDERSeq = (DERSequence) signerAndVeriferRulesTmp;
								DEREncodable signerRules = getAt(
										signerAndVeriferRulesDERSeq, 0);
								if (signerRules instanceof DERSequence) {
									DERSequence signerRulesDERSeq = (DERSequence) signerRules;
									// SignerRules ::= SEQUENCE {
									// externalSignedData BOOLEAN OPTIONAL,
									// -- True if signed data is external to CMS
									// structure
									// -- False if signed data part of CMS
									// structure
									// -- not present if either allowed
									// mandatedSignedAttr CMSAttrs,
									// -- Mandated CMS signed attributes
									// 1.2.840.113549.1.9.3
									// 1.2.840.113549.1.9.4
									// 1.2.840.113549.1.9.16.2.15
									// 1.2.840.113549.1.9.16.2.47
									// mandatedUnsignedAttr CMSAttrs,
									// <empty sequence>
									// -- Mandated CMS unsigned attributed
									// mandatedCertificateRef [0] CertRefReq
									// DEFAULT signerOnly,
									// (1)
									// -- Mandated Certificate Reference
									// mandatedCertificateInfo [1] CertInfoReq
									// DEFAULT none,
									// -- Mandated Certificate Info
									// signPolExtensions [2] SignPolExtensions
									// OPTIONAL}

									// CMSAttrs ::= SEQUENCE OF OBJECT
									// IDENTIFIER
									DEREncodable mandatedSignedAttr = getAt(
											signerRulesDERSeq, 0);
									if (mandatedSignedAttr instanceof DERSequence) {
										DERSequence mandatedSignedAttrDERSeq = (DERSequence) mandatedSignedAttr;
										for (int i = 0; i < mandatedSignedAttrDERSeq
												.size(); i++) {
											DEREncodable at = getAt(
													mandatedSignedAttrDERSeq, i);
											ret.addMandatedSignedAttr(at
													.toString());
										}
									}
									DEREncodable mandatedUnsignedAttr = getAt(
											signerRulesDERSeq, 1);
									if (mandatedUnsignedAttr instanceof DERSequence) {
										DERSequence mandatedUnsignedAttrDERSeq = (DERSequence) mandatedUnsignedAttr;
									}
									DEREncodable mandatedCertificateRef = getAt(
											signerRulesDERSeq, 2);
									if (mandatedCertificateRef instanceof DERTaggedObject) {
										DERTaggedObject mandatedCertificateRefDERSeq = (DERTaggedObject) mandatedCertificateRef;
										// CertRefReq ::= ENUMERATED {
										// signerOnly (1),
										// -- Only reference to signer cert
										// mandated
										// fullpath (2)
										//
										// -- References for full cert path up
										// to a trust point required
										// }
										DEREncodable mandatedCertificateRefTmp = mandatedCertificateRefDERSeq
												.getObject();
										DEREnumerated mandatedCertificateRefEnum = (DEREnumerated) mandatedCertificateRefTmp;
										BigInteger valEnum = mandatedCertificateRefEnum
												.getValue();
										int mandatedCertificateRefInt = valEnum
												.intValue();
										ret.setMandatedCertificateRef(mandatedCertificateRefInt);
									}
								}

								DEREncodable verifierRules = getAt(
										signerAndVeriferRulesDERSeq, 1);
								if (verifierRules instanceof DERSequence) {
									DERSequence verifierRulesDERSeq = (DERSequence) verifierRules;

								}

							}

						}

						DEREncodable signingCertTrustCondition = getAt(
								commonRulesDLS, 1);
						if (signingCertTrustCondition instanceof DERTaggedObject) {
							DERTaggedObject signingCertTrustConditionDTO = (DERTaggedObject) signingCertTrustCondition;
							DEREncodable signingCertTrustConditionTmp = signingCertTrustConditionDTO
									.getObject();
							if (signingCertTrustConditionTmp instanceof DERSequence) {
								DERSequence signingCertTrustConditionDERSeq = (DERSequence) signingCertTrustConditionTmp;
							}

						}
						DEREncodable timeStampTrustCondition = getAt(
								commonRulesDLS, 2);
						if (timeStampTrustCondition instanceof DERTaggedObject) {
							DERTaggedObject timeStampTrustConditionDTO = (DERTaggedObject) timeStampTrustCondition;
							DEREncodable timeStampTrustConditionTmp = timeStampTrustConditionDTO
									.getObject();
							if (timeStampTrustConditionTmp instanceof DERSequence) {
								DERSequence timeStampTrustConditionDERSeq = (DERSequence) timeStampTrustConditionTmp;
							}

						}
						DEREncodable attributeTrustCondition = getAt(
								commonRulesDLS, 3);
						if (attributeTrustCondition instanceof DERTaggedObject) {
							DERTaggedObject attributeTrustConditionDTO = (DERTaggedObject) attributeTrustCondition;
							DEREncodable attributeTrustConditionTmp = attributeTrustConditionDTO
									.getObject();
							if (attributeTrustConditionTmp instanceof DERSequence) {
								DERSequence attributeTrustConditionDERSeq = (DERSequence) attributeTrustConditionTmp;
							}

						}

						// *****************************
						DEREncodable algorithmConstraintSet = getAt(
								commonRulesDLS, 4);
						DEREncodable signPolExtensions = getAt(commonRulesDLS,
								5);

					}
					// commitmentRules CommitmentRules,
					DEREncodable commitmentRules = getAt(
							signatureValidationPolicyDLS, 2);
					if (commitmentRules instanceof ASN1Sequence) {

					}

					// signPolExtensions SignPolExtensions
					// OPTIONAL
					DEREncodable signPolExtensions = getAt(
							signatureValidationPolicyDLS, 3);
					if (signPolExtensions instanceof ASN1Sequence) {

					}
					// }
				}
			}

		}

		// CertInfoReq ::= ENUMERATED {
		// none (0) ,
		// -- No mandatory requirements
		// signerOnly (1) ,
		// -- Only reference to signer cert mandated
		// fullpath (2)
		// -- References for full cert path up to a
		// -- trust point mandated
		// }

		return ret;

	}

	// ********************
	// certificate Service
	// *******************
	public static Map<String, String> createSanMap(byte[] extensionValue,
			int index) {
		Map<String, String> ret = new HashMap<String, String>();
		try {
			if (extensionValue == null) {
				return null;
			}
			ASN1InputStream oAsnInStream = new ASN1InputStream(
					new ByteArrayInputStream(extensionValue));
			DERObject derObjCP = oAsnInStream.readObject();
			ASN1Sequence derSeq = (ASN1Sequence) derObjCP;
			// int seqLen = derSeq.size();
			DERObjectIdentifier oid = (DERObjectIdentifier) derSeq
					.getObjectAt(0);
			String sanOid = oid.getId();

			DERTaggedObject derTO = (DERTaggedObject) derSeq.getObjectAt(1);
			// int tag = derTO.getTagNo();
			DERObject derObjA = derTO.getObject();

			DERTaggedObject derTO2 = (DERTaggedObject) derObjA;
			// int tag2 = derTO2.getTagNo();
			DERObject derObjB = derTO2.getObject();
			String contentStr = "";
			if (derObjB instanceof DEROctetString) {
				DEROctetString derOCStr = (DEROctetString) derObjB;
				contentStr = new String(derOCStr.getOctets(), "UTF8");
			} else if (derObjB instanceof DERPrintableString) {
				DERPrintableString derOCStr = (DERPrintableString) derObjB;
				contentStr = new String(derOCStr.getOctets(), "UTF8");
			} else {
				LOG.error("FORMAT OF SAN: UNRECOGNIZED -> "
						+ derObjB.getClass().getCanonicalName());
			}
			LOG.debug(sanOid + " -> " + contentStr);

			String value = "";
			String name = "";

			if (sanOid.compareTo(PF_PF_ID) == 0
					|| sanOid.compareTo(PJ_PF_ID) == 0) {
				value = contentStr.substring(BIRTH_DATE_INI, BIRTH_DATE_LEN);
				if (isValidValue(value)) {
					name = String.format(CertConstants.BIRTH_DATE_D, index);
					ret.put(name, value);
				}

				value = contentStr.substring(CPF_INI, CPF_LEN);
				if (isValidValue(value)) {
					name = String.format(CertConstants.CPF_D, index);
					ret.put(name, value);
				}

				value = contentStr.substring(PIS_INI, PIS_LEN);
				if (isValidValue(value)) {
					name = String.format(CertConstants.PIS_D, index);
					ret.put(name, value);
				}

				value = contentStr.substring(RG_INI, RG_LEN);
				if (isValidValue(value)) {
					name = String.format(CertConstants.RG_D, index);
					ret.put(name, value);
				}

				int rgOrgUfLen = RG_ORG_UF_LEN > contentStr.length() ? contentStr
						.length() : RG_ORG_UF_LEN;
				if (rgOrgUfLen > RG_ORG_UF_INI) {
					value = contentStr.substring(RG_ORG_UF_INI, rgOrgUfLen);

					String rgOrg = value.substring(0, value.length() - 2);
					String rgUf = value.substring(value.length() - 2,
							value.length());
					if (isValidValue(rgOrg)) {
						name = String.format(CertConstants.RG_ORG_D, index);
						ret.put(name, rgOrg);
					}
					if (isValidValue(rgUf)) {
						name = String.format(CertConstants.RG_UF_D, index);
						ret.put(name, rgUf);
					}
				}

			} else if (sanOid.compareTo(PERSON_NAME_OID) == 0) {
				value = contentStr;
				if (isValidValue(value)) {
					name = String.format(CertConstants.PERSON_NAME_D, index);
					ret.put(name, value);
				}

			} else if (sanOid.compareTo(CNPJ_OID) == 0) {
				name = String.format(CERT_TYPE_FMT, index);
				ret.put(name, ICP_BRASIL_PJ);
				value = contentStr;
				if (isValidValue(value)) {
					name = String.format(CertConstants.CNPJ_D, index);
					ret.put(name, value);
				}

			} else if (sanOid.compareTo(ELEITOR_OID) == 0) {
				name = String.format(CERT_TYPE_FMT, index);
				ret.put(name, ICP_BRASIL_PF);
				value = contentStr.substring(ELEITOR_INI, ELEITOR_LEN);
				if (isValidValue(value)) {
					name = String.format(CertConstants.ELEITOR_D, index);
					ret.put(name, value);
				}

				int zonaLen = ZONA_LEN > contentStr.length() ? contentStr
						.length() : ZONA_LEN;
				if (zonaLen > ZONA_LEN) {

					value = contentStr.substring(ZONA_INI, zonaLen);
					if (isValidValue(value)) {
						name = String.format(CertConstants.ZONA_D, index);
						ret.put(name, value);
					}
				}

				int secaoLen = SECAO_LEN > contentStr.length() ? contentStr
						.length() : SECAO_LEN;
				if (secaoLen > SECAO_LEN) {
					value = contentStr.substring(SECAO_INI, SECAO_LEN);
					if (isValidValue(value)) {
						name = String.format(CertConstants.SECAO_D, index);
						ret.put(name, value);
					}
				}

			} else if (sanOid.compareTo(PF_PF_INSS_OID) == 0
					|| sanOid.compareTo(PJ_PF_INSS_OID) == 0) {
				value = contentStr.substring(INSS_INI, INSS_LEN);
				if (isValidValue(value)) {
					name = String.format(CertConstants.INSS_D, index);
					ret.put(name, value);
				}

			} else if (sanOid.compareTo(OAB_OID) == 0) {
				value = contentStr.substring(OAB_REG_INI, OAB_REG_LEN);
				if (isValidValue(value)) {
					name = String.format(CertConstants.OAB_REG_D, index);
					ret.put(name, value);
				}
				value = contentStr.substring(OAB_UF_INI, OAB_UF_LEN);
				if (isValidValue(value)) {
					name = String.format(CertConstants.OAB_UF_D, index);
					ret.put(name, value);
				}

			} else if (sanOid.startsWith(PROFESSIONAL_OID)) {
				value = contentStr;
				if (isValidValue(value)) {
					name = String.format(CertConstants.PROFESSIONAL_D, index);
					ret.put(name, value);
				}
			} else if (sanOid.startsWith(UPN)) {
				value = contentStr;
				if (isValidValue(value)) {
					name = String.format(CertConstants.UPN_D, index);
					ret.put(name, value);
				}
			} else {
				LOG.error("SAN:OTHER NAME NOT RECOGNIZED");
			}

		} catch (Exception e) {
			LOG.error("Error creating SAN map", e);
		}
		return ret;
	}

	public static byte[] getAKI(byte[] extensionValue, int index) {
		byte[] ret = null;
		try {
			if (extensionValue == null) {
				return null;
			}
			ASN1InputStream oAsnInStream = new ASN1InputStream(
					new ByteArrayInputStream(extensionValue));
			DERObject derObjCP = oAsnInStream.readObject();
			DEROctetString dosCP = (DEROctetString) derObjCP;
			byte[] cpOctets = dosCP.getOctets();
			ASN1InputStream oAsnInStream2 = new ASN1InputStream(
					new ByteArrayInputStream(cpOctets));
			DERObject derObj2 = oAsnInStream2.readObject();
			// derObj2 = oAsnInStream2.readObject();
			ASN1Sequence derSeq = (ASN1Sequence) derObj2;
			int seqLen = derSeq.size();
			// for(int i = 0; i < seqLen; i++){
			DEREncodable derObj3 = derSeq.getObjectAt(0);
			DERTaggedObject derTO = (DERTaggedObject) derObj3;
			int tag = derTO.getTagNo();
			boolean empty = derTO.isEmpty();
			DERObject derObj4 = derTO.getObject();
			DEROctetString ocStr4 = (DEROctetString) derObj4;
			ret = ocStr4.getOctets();
		} catch (Exception e) {
			LOG.error("Error extracting AKI", e);
		}

		return ret;
	}

	public static Map<String, String> getAIAComplete(byte[] ext)
			throws UnsupportedEncodingException {
		Map<String, String> ret = new HashMap<String, String>();
		try {
			if (ext == null)
				return null;
			ASN1InputStream oAsnInStream = new ASN1InputStream(
					new ByteArrayInputStream(ext));
			DERObject derObjAIA = oAsnInStream.readObject();
			DEROctetString dosAia = (DEROctetString) derObjAIA;
			byte[] aiaExtOctets = dosAia.getOctets();

			// ------------ level 2
			ASN1InputStream oAsnInStream2 = new ASN1InputStream(
					new ByteArrayInputStream(aiaExtOctets));
			DERObject derObj2 = oAsnInStream2.readObject();
			ASN1Sequence aiaDLSeq = (ASN1Sequence) derObj2;
			// DEREncodable[] aiaAsArray = aiaDLSeq.toArray();
			int aiaDLSeqLen = aiaDLSeq.size();
			for (int i = 0; i < aiaDLSeqLen; i++) {
				DEREncodable next = aiaDLSeq.getObjectAt(i);
				ASN1Sequence aiaDLSeq2 = (ASN1Sequence) next;
				// DEREncodable[] aiaAsArray2 = aiaDLSeq2.toArray();
				// oid = 0 / content = 1
				DEREncodable aiaOidEnc = aiaDLSeq2.getObjectAt(0);
				DERObjectIdentifier aiaOid = (DERObjectIdentifier) aiaOidEnc;
				String idStr = aiaOid.getId();
				// if (idStr.compareTo("1.3.6.1.5.5.7.48.2") == 0) {
				DEREncodable aiaContent = aiaDLSeq2.getObjectAt(1);
				DERTaggedObject aiaDTO = (DERTaggedObject) aiaContent;
				DERObject aiaObj = aiaDTO.getObject();
				DEROctetString aiaDOS = (DEROctetString) aiaObj;
				byte[] aiaOC = aiaDOS.getOctets();
				ret.put(idStr, new String(aiaOC));
				// break;
				// }
			}

		} catch (Exception e) {
			LOG.error("Error extracting AIA", e);
		}
		return ret;
	}

	public static AlgorithmIdentifier createAlgorithm(int hashId)
			throws Exception {
		return new AlgorithmIdentifier(new DERObjectIdentifier(
				DerEncoder.getHashAlg(hashId)), new DERNull());
	}

	public static Map<String, String> getCertPolicies(byte[] certPols, int index)
			throws CertificateParsingException, IOException {
		Map<String, String> ret = new HashMap<String, String>();
		if (certPols == null) {
			return null;
		}
		ASN1InputStream oAsnInStream = new ASN1InputStream(
				new ByteArrayInputStream(certPols));
		DERObject derObjCP = oAsnInStream.readObject();
		DEROctetString dosCP = (DEROctetString) derObjCP;
		byte[] cpOctets = dosCP.getOctets();
		ASN1InputStream oAsnInStream2 = new ASN1InputStream(
				new ByteArrayInputStream(cpOctets));
		DERObject derObj2 = oAsnInStream2.readObject();
		ASN1Sequence dlCP = (ASN1Sequence) derObj2;
		int seqLen = dlCP.size();
		for (int i = 0; i < seqLen; i++) {
			DEREncodable nextObj = dlCP.getObjectAt(i);
			ASN1Sequence dlCP2 = (ASN1Sequence) nextObj;
			// for(int j = 0; j < dlCP2.size(); j++){
			DEREncodable nextObj2 = dlCP2.getObjectAt(0);
			DERObjectIdentifier pcOID = (DERObjectIdentifier) nextObj2;
			ret.put(String.format(CertConstants.CERT_POL_OID, index),
					pcOID.toString());
			if (pcOID.toString().startsWith(ICP_BRASIL_PC_PREFIX_OID)) {

				ret.put(String.format(CertConstants.CERT_USAGE_D, index),
						getCertUsage(pcOID.toString()));
			}

			if (dlCP2.size() == 2) {
				nextObj2 = dlCP2.getObjectAt(1);

				DEREncodable nextObj3 = null;
				if (nextObj2 instanceof ASN1Sequence) {
					ASN1Sequence dlCP3 = (ASN1Sequence) nextObj2;
					nextObj3 = dlCP3.getObjectAt(0);
				} else if (nextObj2 instanceof DERSequence) {
					DERSequence dlCP3 = (DERSequence) nextObj2;
					if (dlCP3.size() > 1) {
						nextObj3 = dlCP3.getObjectAt(0);
					}

				}
				if (nextObj3 != null) {
					ASN1Sequence dlCP4 = (ASN1Sequence) nextObj3;
					DEREncodable nextObj4a = dlCP4.getObjectAt(0);
					DEREncodable nextObj4b = dlCP4.getObjectAt(1);

					ret.put(String.format(CertConstants.CERT_POL_QUALIFIER,
							index), nextObj4b.toString());
				}
			}
		}
		return ret;

	}

	public static List<String> getCrlDistributionPoints(byte[] crldpExt)
			throws CertificateParsingException, IOException {
		if (crldpExt == null) {
			return new ArrayList<String>();
		}
		ASN1InputStream oAsnInStream = new ASN1InputStream(
				new ByteArrayInputStream(crldpExt));
		DERObject derObjCrlDP = oAsnInStream.readObject();
		DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
		byte[] crldpExtOctets = dosCrlDP.getOctets();
		ASN1InputStream oAsnInStream2 = new ASN1InputStream(
				new ByteArrayInputStream(crldpExtOctets));
		DERObject derObj2 = oAsnInStream2.readObject();
		CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
		List<String> crlUrls = new ArrayList<String>();
		for (DistributionPoint dp : distPoint.getDistributionPoints()) {
			DistributionPointName dpn = dp.getDistributionPoint();
			// Look for URIs in fullName
			if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
				GeneralName[] genNames = GeneralNames
						.getInstance(dpn.getName()).getNames();
				// Look for an URI
				for (int j = 0; j < genNames.length; j++) {
					if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
						String url = DERIA5String.getInstance(
								genNames[j].getName()).getString();
						crlUrls.add(url);
					}
				}
			}
		}
		return crlUrls;
	}

	public static byte[] encodeDigest(DigestInfo dInfo) throws IOException {
		return dInfo.getEncoded(DER);
	}

	public static DEREncodable getAt(ASN1Sequence seq, int index) {
		return seq.size() > index ? seq.getObjectAt(index) : null;
	}

	public static DEREncodable getAt(DERSequence seq, int index) {
		return seq.size() > index ? seq.getObjectAt(index) : null;
	}

	public static boolean isValidValue(String value) {
		boolean ret = true;

		if (value == null || value.length() == 0) {
			ret = false;
		} else {
			String regex = "^0*$";
			Pattern datePatt = Pattern.compile(regex);
			Matcher m = datePatt.matcher(value);
			if (m.matches()) {
				ret = false;
			}
		}
		return ret;
	}

	// 2.16.76.1.2.1.n Identificação de campos associados a Políticas de
	// Certificados
	// do tipo A1
	// 2.16.76.1.2.2.n Identificação de campos associados a Políticas de
	// Certificados c e r t i s i g n . c o m . b r
	// do tipo A2
	// 2.16.76.1.2.3.n Identificação de campos associados a Políticas de
	// Certificados
	// do tipo A3
	// 2.16.76.1.2.4.n Identificação de campos associados a Políticas de
	// Certificados
	// do tipo A4
	// 2.16.76.1.2.101.n Identificação de campos associados a Políticas de
	// Certificados
	// do tipo S1
	// 2.16.76.1.2 2.16.76.1.2....102.n... Identificação de campos associados a
	// Políticas de Certificados
	// do tipo 2
	// 2.16.76.1.2 2.16.76.1.2....103.n... Identificação de campos associados a
	// Políticas de Certificados
	// do tipo S3
	// 2.16.76.1.2 2.16.76.1.2....104.n... Identificação de campos associados a
	// Políticas de Certificados
	// do tipo S4
	private static String getCertUsage(String pcOid) {
		String ret = "";

		if (pcOid.startsWith("2.16.76.1.2.1")) {
			ret = "ICP-Brasil A1";
		} else if (pcOid.startsWith("2.16.76.1.2.2")) {
			ret = "ICP-Brasil A2";
		} else if (pcOid.startsWith("2.16.76.1.2.3")) {
			ret = "ICP-Brasil A3";
		} else if (pcOid.startsWith("2.16.76.1.2.4")) {
			ret = "ICP-Brasil A4";
		} else if (pcOid.startsWith("2.16.76.1.2.101")) {
			ret = "ICP-Brasil S1";
		} else if (pcOid.startsWith("2.16.76.1.2.102")) {
			ret = "ICP-Brasil S2";
		} else if (pcOid.startsWith("2.16.76.1.2.103")) {
			ret = "ICP-Brasil S3";
		} else if (pcOid.startsWith("2.16.76.1.2.104")) {
			ret = "ICP-Brasil S4";
		}
		return ret;
	}

	public static OCSPReq GenOcspReq(X509Certificate nextCert,
			X509Certificate nextIssuer) throws OCSPException {

		OCSPReqGenerator ocspRequestGenerator = new OCSPReqGenerator();
		CertificateID certId = new CertificateID(CertificateID.HASH_SHA1,
				nextIssuer, nextCert.getSerialNumber());
		ocspRequestGenerator.addRequest(certId);

		BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
		Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
		Vector<X509Extension> values = new Vector<X509Extension>();

		oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		values.add(new X509Extension(false, new DEROctetString(nonce
				.toByteArray())));

		ocspRequestGenerator.setRequestExtensions(new X509Extensions(oids,
				values));
		return ocspRequestGenerator.generate();
	}

	public static List<String> extractOCSPUrl(X509Certificate nextCert)
			throws CRLException {
		List<String> OCSPUrl = new ArrayList<String>();
		// LOG.debug("MISSING!!");

		DERObject aiaExt = getExtensionValue(nextCert,
				X509Extensions.AuthorityInfoAccess.getId());
		if (aiaExt != null) {
			extractAuthorityInformationAccess(OCSPUrl, aiaExt);
		}
		return OCSPUrl;
	}

	public static void extractAuthorityInformationAccess(List<String> OCSPUrl,
			DERObject aiaExt) {
		AuthorityInformationAccess aia = AuthorityInformationAccess
				.getInstance(aiaExt);
		AccessDescription[] accessDescriptions = aia.getAccessDescriptions();
		DERObjectIdentifier OCSPOid = new DERObjectIdentifier(
				"1.3.6.1.5.5.7.48.1"); //$NON-NLS-1$
		for (AccessDescription accessDescription : accessDescriptions) {
			GeneralName generalName = accessDescription.getAccessLocation();
			String nextName = generalName.getName().toString();
			DERObjectIdentifier acessMethod = accessDescription
					.getAccessMethod();
			if (acessMethod.equals(OCSPOid)) {
				OCSPUrl.add(nextName);
			}
		}
	}

	protected static DERObject getExtensionValue(
			java.security.cert.X509Extension ext, String oid)
			throws CRLException {
		byte[] bytes = ext.getExtensionValue(oid);
		if (bytes == null) {
			return null;
		}

		return getObject(oid, bytes);
	}

	private static DERObject getObject(String oid, byte[] ext)
			throws CRLException {
		try {
			ASN1InputStream aIn = new ASN1InputStream(ext);
			ASN1OctetString octs = (ASN1OctetString) aIn.readObject();

			aIn = new ASN1InputStream(octs.getOctets());
			return aIn.readObject();
		} catch (Exception e) {

			LOG.error("CRLException - exception processing extension " + oid, e);
			throw new CRLException("exception processing extension " + oid, e); //$NON-NLS-1$
		}
	}

	public static byte[] convSiToByte(ASN1Set newSi) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		ASN1OutputStream aOut = new ASN1OutputStream(bOut);

		aOut.writeObject(newSi);

		aOut.close();

		byte[] saAsBytes = bOut.toByteArray();
		return saAsBytes;
	}
}
