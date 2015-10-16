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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import bluecrystal.bcdeps.helper.DerEncoder;
import bluecrystal.bcdeps.helper.PkiOps;
import bluecrystal.domain.CertConstants;
import bluecrystal.domain.CertStatus;
import bluecrystal.domain.CiKeyUsage;
import bluecrystal.domain.StatusConst;
import bluecrystal.domain.helper.IttruLoggerFactory;
import bluecrystal.service.exception.RevokedException;
import bluecrystal.service.exception.UndefStateException;
import bluecrystal.service.helper.Utils;
import bluecrystal.service.loader.LCRLoaderImpl;
import bluecrystal.service.validator.CrlValidatorImpl;
import bluecrystal.service.validator.OcspValidatorImpl;
import bluecrystal.service.validator.StatusValidator;
import bluecrystal.service.validator.StatusValidatorImpl;

public class CertificateService {
	static final Logger LOG = LoggerFactory.getLogger(CertificateService.class);

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
	// PF 2.16.76.1.3.1 - Data Nascimento(8) , CPF(11), NIS (PIS, PASEP ou CI)
	// (11), RG (15), orgão e UF (6).

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
	// private static final int OAB_REG_INI = 0;
	// private static final int OAB_REG_LEN = 12;
	// private static final int OAB_UF_INI = OAB_REG_LEN;
	// private static final int OAB_UF_LEN = 3;

	private static final int SAN_OTHER_NAME = 0;
	private static final int SAN_EMAIL = 1;

	private static final String AKI_OID = "2.5.29.35";
	// private static final String BASIC_CONSTRAINTS = "2.5.29.19";
	// private static final String CERT_POL_QUALIFIER = "certPolQualifier%d";
	// private static final String CERT_POL_OID = "certPolOid%d";
	private static final String CERT_POLICIES = "2.5.29.32";
	private static final String CRL_DIST_POINT = "2.5.29.31";
	public static final String OCSP = "1.3.6.1.5.5.7.48.1";
	private static final String CA_ISSUERS = "1.3.6.1.5.5.7.48.2";

	private static final String AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";
	private static final String NON_REPUDIATION = "nonRepudiation";
	private static final String KEY_ENCIPHERMENT = "keyEncipherment";
	private static final String KEY_CERT_SIGN = "keyCertSign";
	private static final String KEY_AGREEMENT = "keyAgreement";
	private static final String ENCIPHER_ONLY = "encipherOnly";
	private static final String DECIPHER_ONLY = "decipherOnly";
	private static final String DATA_ENCIPHERMENT = "dataEncipherment";
	private static final String CRL_SIGN = "cRLSign";
	private static final String LIST_FORMAT = "%s,";
	private static final String DIGITAL_SIGNATURE = "digitalSignature";
	private List<X509Certificate> intermCa;
	private List<X509Certificate> trustAnchor;
	Map<String, X509Certificate> mapInterm = null;
	Map<String, X509Certificate> mapAnchor = null;
	StatusValidator statusValidator;
	boolean enforceKu;
	int minKeyLen = 2048;
	private String[] ignore = { "2.5.29.15", // key usage
			"2.5.29.37", // extende key usage
			"2.5.29.19", // basic constraints
			"2.5.29.17" // san

	};

	// 5.2.3.1.1.2 Tamanho Mínimo de Chave
	// O tamanho mínimo de chaves para criação de assinaturas segundo esta PA é
	// de :
	// a) para a versão 1.0: 1024 bits;
	// b) para a versão 1.1: 1024 bits;
	// b) para as versões 2.0 e 2.1: 2048 bits.

	public CertificateService() {
		super();
		OcspValidatorImpl ocspValidator = new OcspValidatorImpl();
		// OcspValidatorImpl ocspValidator = null;
		LCRLoaderImpl lcrLoader = new LCRLoaderImpl();
		CrlValidatorImpl crlValidator = new CrlValidatorImpl(lcrLoader);
		statusValidator = new StatusValidatorImpl(crlValidator, ocspValidator);
		statusValidator.setUseOcsp(true);
		org.bouncycastle.jce.provider.BouncyCastleProvider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(provider);
		enforceKu = false;
		minKeyLen = 2048;
	}

	public X509Certificate createFromB64(byte[] certB64)
			throws CertificateException {
		ByteArrayInputStream is = new ByteArrayInputStream(certB64);
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		Certificate c = cf.generateCertificate(is);
		return (X509Certificate) c;
	}

	public List<X509Certificate> getIntermCaList() throws Exception {
		if (intermCa == null) {
			intermCa = Utils.listCertFromRepo("interm");
			mapInterm = buildMap(intermCa);
		}
		return intermCa;
	}

	public List<X509Certificate> getTrustAnchorList() throws Exception {
		if (trustAnchor == null) {
			trustAnchor = Utils.listCertFromRepo("root");
			mapAnchor = buildMap(trustAnchor);
		}
		return trustAnchor;
	}

	// public CertStatus isValidForSign(String certName, Date refDate)
	// throws Exception {
	// X509Certificate cert = Utils.loadCertFromS3(certName);
	// return isValidForSign(refDate, cert);
	//
	// }

	public CertStatus isValidForSign(Date refDate, X509Certificate cert)
			throws Exception, IOException, CertificateException, CRLException,
			UndefStateException, RevokedException {
		RSAKey rsaKey = (RSAKey) (cert.getPublicKey());
		int keySize = rsaKey.getModulus().bitLength();
		if (!forSign(cert) || keySize < minKeyLen) {
			return new CertStatus(StatusConst.UNSABLEKEY, null);
		}
		return isValid(refDate, cert);
	}

	public Map<String, String> parseChainAsMap(List<X509Certificate> chain) {
		Map<String, String> ret = new HashMap<String, String>();

		int i = 0;
		for (X509Certificate next : chain) {
			LOG.debug("CERT:" + next.getSubjectDN().getName());
			try {
				String name = "";
				String value = "";

				value = next.getSubjectDN().getName();
				name = String.format(CertConstants.SUBJECT_D, i);
				ret.put(name, value);

				value = next.getIssuerDN().getName();
				name = String.format(CertConstants.ISSUER_D, i);
				ret.put(name, value);

				value = String.valueOf(next.getNotAfter().getTime());
				name = String.format(CertConstants.NOT_AFTER_D, i);
				ret.put(name, value);

				value = String.valueOf(next.getNotBefore().getTime());
				name = String.format(CertConstants.NOT_BEFORE_D, i);
				ret.put(name, value);

				value = String.valueOf(next.getVersion());
				name = String.format(CertConstants.VERSION_D, i);
				ret.put(name, value);

				value = String.valueOf(calcCertSha256(next));
				name = String.format(CertConstants.CERT_SHA256_D, i);
				ret.put(name, value);

				value = next.getSerialNumber().toString();
				name = String.format(CertConstants.SERIAL_D, i);
				ret.put(name, value);

				PublicKey pubKey = next.getPublicKey();
				RSAPublicKey rsaPubKey = (RSAPublicKey) pubKey;
				value = String.valueOf(rsaPubKey.getModulus().bitLength());
				name = String.format(CertConstants.KEY_LENGTH_D, i);
				ret.put(name, value);

				int basicConstraint = next.getBasicConstraints();
				value = String.valueOf(basicConstraint);
				name = String.format(CertConstants.BASIC_CONSTRAINT_D, i);
				ret.put(name, value);

				// GeneralName ::= CHOICE {
				// otherName [0] OtherName,
				// rfc822Name [1] IA5String,
				// dNSName [2] IA5String,
				// x400Address [3] ORAddress,
				// directoryName [4] Name,
				// ediPartyName [5] EDIPartyName,
				// uniformResourceIdentifier [6] IA5String,
				// iPAddress [7] OCTET STRING,
				// registeredID [8] OBJECT IDENTIFIER }

				value = "standard";
				name = String.format(CERT_TYPE_FMT, i);
				ret.put(name, value);

				Collection<List<?>> sanList = next.getSubjectAlternativeNames();
				if (sanList != null) {
					for (List<?> nextSan : sanList) {
						try {
							Integer san1 = (Integer) nextSan.get(0);
							Object san2 = nextSan.get(1);
							if (san1 == SAN_OTHER_NAME) {
								if (san2 instanceof String) {
									LOG.error("UNSUPORTED OTHERNAME SAN FORMAT");
								} else {
									Map<String, String> otherNameMap = createSanMap(
											(byte[]) san2, i);
									ret.putAll(otherNameMap);
								}

							} else if (san1 == SAN_EMAIL) {
								if (san2 instanceof String) {
									name = String.format(
											CertConstants.SAN_EMAIL_D, i);
									ret.put(name, (String) san2);
								} else {
									LOG.error("UNSUPORTED EMAIL SAN FORMAT");
								}
							} else {
								LOG.error("UNSUPORTED SAN");
							}

						} catch (Exception e) {
							LOG.error("Erroe decoding SAN", e);
						}

					}
				}

				List<String> extKU = next.getExtendedKeyUsage();
				StringBuffer finalEKU = new StringBuffer();
				if (extKU != null) {
					for (String nextEKU : extKU) {
						String translEKU = translateEKU(nextEKU);
						finalEKU.append(String.format(LIST_FORMAT, translEKU));
					}
					value = finalEKU.substring(0, finalEKU.length() - 2); // remove
																			// last
																			// SPACE
																			// +
																			// comma
					name = String.format(CertConstants.EKU_D, i);
					ret.put(name, value);
				}

				StringBuffer finalKU = new StringBuffer();
				boolean[] ku = next.getKeyUsage();
				if (ku != null) {
					finalKU.append(ku[CiKeyUsage.cRLSign] ? String.format(
							LIST_FORMAT, CRL_SIGN) : "");
					finalKU.append(ku[CiKeyUsage.dataEncipherment] ? String
							.format(LIST_FORMAT, DATA_ENCIPHERMENT) : "");
					finalKU.append(ku[CiKeyUsage.decipherOnly] ? String.format(
							LIST_FORMAT, DECIPHER_ONLY) : "");
					finalKU.append(ku[CiKeyUsage.digitalSignature] ? String
							.format(LIST_FORMAT, DIGITAL_SIGNATURE) : "");
					finalKU.append(ku[CiKeyUsage.encipherOnly] ? String.format(
							LIST_FORMAT, ENCIPHER_ONLY) : "");
					finalKU.append(ku[CiKeyUsage.keyAgreement] ? String.format(
							LIST_FORMAT, KEY_AGREEMENT) : "");
					finalKU.append(ku[CiKeyUsage.keyCertSign] ? String.format(
							LIST_FORMAT, KEY_CERT_SIGN) : "");
					finalKU.append(ku[CiKeyUsage.keyEncipherment] ? String
							.format(LIST_FORMAT, KEY_ENCIPHERMENT) : "");
					finalKU.append(ku[CiKeyUsage.nonRepudiation] ? String
							.format(LIST_FORMAT, NON_REPUDIATION) : "");

					value = finalKU.substring(0, finalKU.length() - 1); // remove
																		// last
				} // comma
				name = String.format(CertConstants.KU_D, i);
				ret.put(name, value);

				LOG.debug("** getCriticalExtensionOIDs");
				Set<String> critOIDs = next.getCriticalExtensionOIDs();
				if (critOIDs != null) {
					for (String critOID : critOIDs) {
						LOG.debug(String.format("%s -> %s", critOID,
								next.getExtensionValue(critOID)));
						if (!shouldIgnore(critOID)) {
							LOG.debug(" no extension beeing processed.");
						} else {
							LOG.debug(String.format("IGNORE: %s", critOID));
						}
					}
				}

				LOG.debug("** getNonCriticalExtensionOIDs");
				Set<String> nonCritOIDs = next.getNonCriticalExtensionOIDs();
				if (nonCritOIDs != null) {
					for (String nonCritOID : nonCritOIDs) {
						LOG.debug(String.format("%s -> %s", nonCritOID,
								new String(next.getExtensionValue(nonCritOID))));

						if (!shouldIgnore(nonCritOID)) {
							LOG.debug("no extension beeing processed.");
							Map<String, String> extensionMap = processExtension(
									nonCritOID,
									next.getExtensionValue(nonCritOID), i);
							ret.putAll(extensionMap);
						} else {
							LOG.debug(String.format("IGNORE: %s", nonCritOID));

						}
					}
				}

			} catch (Exception e) {
				LOG.error("Error decoding X.509 field or exception", e);
			}

			i++;
		}

		return ret;

	}

	private String calcCertSha256(X509Certificate next) {
		String ret = "";
		PkiOps pki = new PkiOps();
		String certSha256;
		try {
			ret = Utils.conv(pki.calcSha256(next.getEncoded()));
		} catch (Exception e) {
			LOG.error("Error calculating cert sha256 ", e);
		}
		return ret;
	}

	private String translateEKU(String nextEKU) {
		String ret = "";

		if (nextEKU.compareTo(EKU_OCSP_SIGN_OID) == 0) {
			ret = "ekuOcspSign";
		} else if (nextEKU.compareTo(EKU_TIMESTAMP_OID) == 0) {
			ret = "ekuTimeStamp";
		} else if (nextEKU.compareTo(EKU_IPSEC_USER_OID) == 0) {
			ret = "ekuIpSecUser";
		} else if (nextEKU.compareTo(EKU_IPSEC_TUNNEL_OID) == 0) {
			ret = "ekuIpSecTunnel";
		} else if (nextEKU.compareTo(EKU_IPSEC_END_OID) == 0) {
			ret = "ekuIpSecEnd";
		} else if (nextEKU.compareTo(EKU_EMAIL_PROT_OID) == 0) {
			ret = "ekuEmailProt";
		} else if (nextEKU.compareTo(EKU_CODE_SIGN_OID) == 0) {
			ret = "ekuCodeSgin";
		} else if (nextEKU.compareTo(EKU_CLIENT_AUTH_OID) == 0) {
			ret = "ekuClientAuth";
		} else if (nextEKU.compareTo(EKU_SERVER_AUTH_OID) == 0) {
			ret = "ekuServerAuth";
		}
		return ret;
	}

	private Map<String, String> createSanMap(byte[] extensionValue, int index) {
		return DerEncoder.createSanMap(extensionValue, index);

	}

	private Map<String, String> processExtension(String nonCritOID,
			byte[] extensionValue, int index) {
		Map<String, String> nvPair = new HashMap<String, String>();
		try {
			if (nonCritOID.compareTo(AUTHORITY_INFO_ACCESS) == 0) {
				Map<String, String> aia = getAIAComplete(extensionValue);
				nvPair.putAll(convertAiaOid(aia, index));
			} else if (nonCritOID.compareTo(CRL_DIST_POINT) == 0) {
				List<String> crlDP = getCrlDistributionPoints(extensionValue);
				StringBuffer finalCDP = new StringBuffer();
				for (String nextCDP : crlDP) {
					finalCDP.append(String.format(LIST_FORMAT, nextCDP));
				}
				nvPair.put(String.format(CertConstants.CRL_DP, index),
						finalCDP.substring(0, finalCDP.length() - 1));
			} else if (nonCritOID.compareTo(CERT_POLICIES) == 0) {
				Map<String, String> certPol = getCertPolicies(extensionValue,
						index);
				nvPair.putAll(certPol);
			} else if (nonCritOID.compareTo(AKI_OID) == 0) {
				byte[] aki = getAKI(extensionValue, index);
				nvPair.put(String.format(CertConstants.AKI_FMT, index),
						Utils.conv(aki));
			}
		} catch (Exception e) {
			LOG.error("Error processing extension " + nonCritOID, e);
		}
		return nvPair;
	}

	private byte[] getAKI(byte[] extensionValue, int index) {
		return DerEncoder.getAKI(extensionValue, index);
	}

	private Map<String, String> convertAiaOid(Map<String, String> aia, int index) {
		Map<String, String> nvPair = new HashMap<String, String>();

		for (String next : aia.keySet()) {
			if (next.compareTo(OCSP) == 0) {
				nvPair.put(String.format(CertConstants.OCSP_STR, index),
						aia.get(OCSP));
			} else if (next.compareTo(CA_ISSUERS) == 0) {
				nvPair.put(String.format(CertConstants.CA_ISSUERS_STR, index),
						aia.get(CA_ISSUERS));
			}
		}
		return nvPair;
	}

	private boolean shouldIgnore(String critOID) {
		boolean ret = false;
		for (String nextIgnore : ignore) {
			if (nextIgnore.compareTo(critOID) == 0) {
				ret = true;
				break;
			}
		}
		return ret;
	}

	private boolean forSign(X509Certificate cert) {
		// KeyUsage ::= BIT STRING {
		// digitalSignature (0),
		// nonRepudiation (1),
		// keyEncipherment (2),
		// dataEncipherment (3),
		// keyAgreement (4),
		// keyCertSign (5),
		// cRLSign (6),
		// encipherOnly (7),
		// decipherOnly (8) }

		// The digitalSignature bit is asserted when the subject public key
		// is used for verifying digital signatures, other than signatures on
		// certificates (bit 5) and CRLs (bit 6), such as those used in an
		// entity authentication service, a data origin authentication
		// service, and/or an integrity service.

		// The nonRepudiation bit is asserted when the subject public key is
		// used to verify digital signatures, other than signatures on
		// certificates (bit 5) and CRLs (bit 6), used to provide a non-
		// repudiation service that protects against the signing entity
		// falsely denying some action. In the case of later conflict, a
		// reliable third party may determine the authenticity of the signed
		// data. (Note that recent editions of X.509 have renamed the
		// nonRepudiation bit to contentCommitment.)

		boolean[] ku = cert.getKeyUsage();
		return enforceKu ? ku[CiKeyUsage.digitalSignature]
				&& ku[CiKeyUsage.nonRepudiation]
				: ku[CiKeyUsage.digitalSignature]
						|| ku[CiKeyUsage.nonRepudiation];
	}

	public CertStatus isValid(Date refDate, X509Certificate cert)
			throws Exception, IOException, CertificateException, CRLException,
			UndefStateException, RevokedException {
		return isValid(refDate, cert, true);
	}

	public CertStatus isValid(Date refDate, X509Certificate cert,
			boolean verifyRevoke) throws Exception, IOException,
			CertificateException, CRLException, UndefStateException,
			RevokedException {
		CertStatus ret = new CertStatus(StatusConst.UNKNOWN, null);
		List<X509Certificate> certsOnPath = buildPath(cert);
		if (certsOnPath != null) {

			try {
				verificaCertPath(certsOnPath, refDate);
				if (verifyRevoke) {
					ret = statusValidator.verifyStatusEE(certsOnPath, refDate,
							this.getCrlDistributionPoints(cert));
				}
			} catch (Exception e) {
				ret = new CertStatus(StatusConst.UNTRUSTED, null);
			}

		} else {
			LOG.error("** ERROR:certsOnPath == null " + new Date());
			ret = new CertStatus(StatusConst.UNTRUSTED, null);
		}
		return ret;
	}

	public List<X509Certificate> buildPath(X509Certificate signerCert)
			throws Exception {

		return buildPath(signerCert, getIntermCaList(), getTrustAnchorList());
	}

	public List<X509Certificate> decode(byte[] encoded)
			throws CertificateException, IOException, CRLException {
		List<X509Certificate> certs = new ArrayList<X509Certificate>();

		try {
			List<byte[]> bList = DerEncoder.extractCertList(encoded);

			for (byte[] b : bList) {
				// saveToFile(b);
				InputStream inStream = new ByteArrayInputStream(b);
				CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
				List<X509Certificate> certsTemp = (List<X509Certificate>) cf
						.generateCertificates(inStream);
				certs.addAll(certsTemp);
				inStream.close();

			}

		} catch (Exception e) {
			LOG.error("Error decoding X.509 cert from bytes ", e);
		}

		return certs;
	}

	public X509Certificate decodeEE(byte[] encoded)
			throws CertificateException, IOException, CRLException {
		List<X509Certificate> ret = decode(encoded);
		for (X509Certificate next : ret) {
			if (isEE(next)) {
				return next;
			}
		}
		return null;
	}

	private static boolean isEE(X509Certificate nextCert) {
		return nextCert.getBasicConstraints() == -1;
	}

	private static List<X509Certificate> buildPath(X509Certificate signer,
			Collection<X509Certificate> intermCa,
			Collection<X509Certificate> trustAnchor) throws Exception {
		List<X509Certificate> certsOnPath = new ArrayList<X509Certificate>();

		LOG.debug("****** Signer Issuer");
		LOG.debug(signer.getIssuerDN().getName());
		//
		LOG.debug("****** intermCa");
		Map<String, X509Certificate> mapInterm = buildMap(intermCa);
		LOG.debug("****** rootCa");
		Map<String, X509Certificate> mapAnchor = buildMap(trustAnchor);

		certsOnPath.add(signer);

		X509Certificate nextCert = signer;
		while (mapInterm.containsKey((String) nextCert.getIssuerDN().getName())) {
			certsOnPath.add(mapInterm.get((String) nextCert.getIssuerDN()
					.getName()));
			nextCert = mapInterm.get((String) nextCert.getIssuerDN().getName());
		}
		if (mapAnchor.containsKey((String) nextCert.getIssuerDN().getName())) {
			certsOnPath.add(mapAnchor.get((String) nextCert.getIssuerDN()
					.getName()));
		} else {
			List<X509Certificate> aiaPath = buildPathUsingAIA(signer);
			Map<String, X509Certificate> mapAiaInterm = buildMap(aiaPath);
			nextCert = signer;

			while (mapAiaInterm.containsKey((String) nextCert.getIssuerDN()
					.getName())) {
				certsOnPath.add(mapAiaInterm.get((String) nextCert
						.getIssuerDN().getName()));
				nextCert = mapAiaInterm.get((String) nextCert.getIssuerDN()
						.getName());
			}
			if (mapAnchor
					.containsKey((String) nextCert.getIssuerDN().getName())) {
				certsOnPath.add(mapAnchor.get((String) nextCert.getIssuerDN()
						.getName()));
			}
		}
		return certsOnPath;
	}

	public static List<X509Certificate> buildPathUsingAIA(X509Certificate signer)
			throws Exception {
		List<X509Certificate> certsInterm = new ArrayList<X509Certificate>();
		String aiaUrlStr = getAIA(signer);
		if (aiaUrlStr != null) {
			List<X509Certificate> certs = loadCerts(new URL(aiaUrlStr));
			for (X509Certificate nextCert : certs) {
				if (!isRoot(nextCert)) {
					certsInterm.add(nextCert);
				}
			}
		}
		return certsInterm;
	}

	public static boolean isRoot(X509Certificate cert) {
		String subj = cert.getSubjectDN().toString();
		String issuer = cert.getIssuerDN().toString();
		return subj.compareTo(issuer) == 0;

	}

	private static List<X509Certificate> loadCerts(URL url) throws Exception {
		InputStream is = url.openStream();
		List<X509Certificate> retList = new ArrayList<X509Certificate>();
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		Collection<? extends Certificate> c = cf.generateCertificates(is);

		for (Certificate next : c) {
			retList.add((X509Certificate) next);
		}
		return retList;
	}

	private static Map<String, X509Certificate> buildMap(
			Collection<X509Certificate> list) {
		Map<String, X509Certificate> map = new HashMap<String, X509Certificate>();
		Iterator<X509Certificate> it = list.iterator();

		while (it.hasNext()) {
			X509Certificate nextCert = it.next();
			LOG.debug(nextCert.getSubjectDN().getName());
			map.put(nextCert.getSubjectDN().getName(), nextCert);
		}
		return map;
	}

	private void verificaCertPath(Collection<X509Certificate> certsOnPath,
			Date dtData) throws Exception {

		CertPath certPath = createCertPathToValidate(certsOnPath);

		PKIXParameters params = null;
		params = createPKIXParms(trustAnchor, dtData);

		params.setRevocationEnabled(false);
		if (certPathReview(certPath, params) == null) {
			throw new RuntimeException(""); //$NON-NLS-1$
		}
	}

	private PKIXCertPathValidatorResult certPathReview(CertPath certPath,
			PKIXParameters params) throws NoSuchAlgorithmException,
			CertPathValidatorException, InvalidAlgorithmParameterException {

		CertPathValidator certPathValidator = CertPathValidator
				.getInstance(CertPathValidator.getDefaultType());
		CertPathValidatorResult result = certPathValidator.validate(certPath,
				params);

		PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult) result;

		return pkixResult;

	}

	private PKIXParameters createPKIXParms(
			Collection<X509Certificate> trustAnchorColl, Date dtDate)
			throws InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		Set tmpTA = new HashSet();
		Iterator<X509Certificate> itLast = trustAnchorColl.iterator();
		while (itLast.hasNext()) {
			X509Certificate certOnPath = itLast.next();
			TrustAnchor trustAnchor = new TrustAnchor(certOnPath, null);
			tmpTA.add(trustAnchor);
		}

		PKIXParameters params = new PKIXParameters(tmpTA);
		params.setDate(dtDate);
		return params;

	}

	private CertPath createCertPathToValidate(
			Collection<X509Certificate> certsOnPath)
			throws CertificateException {
		X509Certificate[] certPathToValidate = null;
		certPathToValidate = new X509Certificate[certsOnPath.size()];
		Iterator<X509Certificate> itLast = certsOnPath.iterator();
		int cnt = 0;
		while (itLast.hasNext()) {
			X509Certificate certOnPath = itLast.next();
			certPathToValidate[cnt] = certOnPath;
			cnt++;
		}
		CertificateFactory certFact = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		CertPath path = certFact.generateCertPath(Arrays
				.asList(certPathToValidate));
		return path;
	}

	public static String getAIA(X509Certificate cert)
			throws UnsupportedEncodingException {
		String ret = null;
		byte[] ext = cert.getExtensionValue(AUTHORITY_INFO_ACCESS);
		Map<String, String> aia = getAIAComplete(ext);
		if (aia != null) {
			ret = aia.get(CA_ISSUERS);
		}

		return ret;
	}

	public static Map<String, String> getAIAComplete(byte[] ext)
			throws UnsupportedEncodingException {
		return DerEncoder.getAIAComplete(ext);
	}

	public static List<String> getCrlDistributionPoints(X509Certificate cert)
			throws CertificateParsingException, IOException {
		// String extOid = X509Extensions.CRLDistributionPoints.getId();
		String extOid = "2.5.29.31";

		byte[] crldpExt = cert.getExtensionValue(extOid);
		return getCrlDistributionPoints(crldpExt);
	}

	public static List<String> getCrlDistributionPoints(byte[] crldpExt)
			throws CertificateParsingException, IOException {

		return DerEncoder.getCrlDistributionPoints(crldpExt);
	}

	public static Map<String, String> getCertPolicies(byte[] certPols, int index)
			throws CertificateParsingException, IOException {
		return DerEncoder.getCertPolicies(certPols, index);

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
}
