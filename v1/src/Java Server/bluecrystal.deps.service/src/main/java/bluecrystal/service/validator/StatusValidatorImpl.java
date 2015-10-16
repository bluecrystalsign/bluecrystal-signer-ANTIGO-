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

package bluecrystal.service.validator;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import bluecrystal.domain.CertStatus;
import bluecrystal.domain.StatusConst;
import bluecrystal.domain.helper.IttruLoggerFactory;
import bluecrystal.service.exception.RevokedException;
import bluecrystal.service.exception.UndefStateException;

public class StatusValidatorImpl implements StatusValidator {
	static final Logger LOG = LoggerFactory.getLogger(StatusValidatorImpl.class);

	private boolean useOcsp;

	private OcspValidator ocspValidator;
	private CrlValidator crlValidator;

	public StatusValidatorImpl(CrlValidator crlValidator,
			OcspValidator ocspValidator) {
		super();
		this.ocspValidator = ocspValidator;
		this.crlValidator = crlValidator;
	}

	public void setUseOcsp(boolean useOcsp) {
		this.useOcsp = useOcsp;
	}

	public CertStatus verifyStatusEE(Collection<X509Certificate> certsOnPath, 
			Date date, List<String> crlDist)
			throws IOException, CertificateException, CRLException,
			UndefStateException, RevokedException {
		Iterator<X509Certificate> it = certsOnPath.iterator();
		CertStatus eeCertStatus = new CertStatus(StatusConst.GOOD, null);
		CertStatus nextCertStatus = new CertStatus(StatusConst.GOOD, null);

		X509Certificate nextCert = null;
		X509Certificate nextIssuer = null;

		// First cert is EE
		if (it.hasNext()) {
			nextCert = it.next();
			LOG.debug("** EE - VALIDATING: "+nextCert.getSubjectDN().getName()+ " " + new Date());
			nextCertStatus = crlValidator.verifyLCR(nextCert, date, crlDist);
			eeCertStatus = nextCertStatus;
		} else {
			LOG.error("** ERROR: nenhum certificado na hierarquia! " + new Date());
		}

		if (it.hasNext() && useOcsp) {
//			while (it.hasNext() && useOcsp) {
			nextIssuer = it.next();
			if (nextCertStatus.getStatus() == StatusConst.UNKNOWN) {
				if (useOcsp) {
					LOG.debug("validating OCSP");
					try {
						nextCertStatus = ocspValidator.verifyOCSP(nextCert,
								nextIssuer, date);
					} catch (Exception e) {
//						se deu excecao, ok. Continua com o status anterior.
					}
				}
				if (isEE(nextCert)) {
					eeCertStatus = nextCertStatus;
				}
			}
		}

		LOG.debug("Cert bom até .."+eeCertStatus.getGoodUntil());
		return eeCertStatus;
	}

	
	
	public CertStatus verifyStatus(Collection<X509Certificate> certsOnPath, Date date)
			throws IOException, CertificateException, CRLException,
			UndefStateException, RevokedException {
		Iterator<X509Certificate> it = certsOnPath.iterator();
		CertStatus eeCertStatus = new CertStatus(StatusConst.GOOD, null);
		CertStatus nextCertStatus = new CertStatus(StatusConst.GOOD, null);

		X509Certificate nextCert = null;
		X509Certificate nextIssuer = null;

		// First cert is EE
		if (it.hasNext()) {
			nextCert = it.next();
			LOG.debug("** EE - VALIDATING: "+nextCert.getSubjectDN().getName()+ " " + new Date());
			nextCertStatus = crlValidator.verifyLCR(nextCert, date, null);
			eeCertStatus = nextCertStatus;
		}

		while (it.hasNext() && useOcsp) {
			nextIssuer = it.next();
			if (nextCertStatus.getStatus() == StatusConst.UNKNOWN) {
				if (useOcsp) {
					nextCertStatus = ocspValidator.verifyOCSP(nextCert,
							nextIssuer, date);
				}
				if (isEE(nextCert)) {
					eeCertStatus = nextCertStatus;
				}
			}
			nextCert = nextIssuer;
			LOG.debug("VALIDATING: "+nextCert.getSubjectDN().getName()+ " " + new Date());
			nextCertStatus = crlValidator.verifyLCR(nextCert, date, null);
		}

		if (useOcsp) {
			ocspValidator.verifyOCSP(nextCert, nextCert, date);
			if (eeCertStatus.getStatus() == StatusConst.UNKNOWN) {
				throw new UndefStateException();
			}
		}
		return eeCertStatus;
	}
	
	
	private static boolean isEE(X509Certificate nextCert) {
		return nextCert.getBasicConstraints() == -1;
	}

}
