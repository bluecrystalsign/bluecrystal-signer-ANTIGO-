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
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import bluecrystal.domain.CertStatus;
import bluecrystal.domain.StatusConst;
import bluecrystal.service.exception.RevokedException;
import bluecrystal.service.exception.UndefStateException;
import bluecrystal.service.loader.LCRLoader;

public class CrlValidatorImpl implements CrlValidator {
	static final Logger LOG = LoggerFactory.getLogger(CrlValidatorImpl.class);
	private LCRLoader lcrLoader;

	public CrlValidatorImpl(LCRLoader lcrLoader) {
		super();
		this.lcrLoader = lcrLoader;
	}

	public CertStatus verifyLCR(X509Certificate nextCert, 
			Date date, List<String> distPoints)
			throws IOException, CertificateException, CRLException,
			UndefStateException, RevokedException {

//		List<String> distPoints = getCrlDistributionPoints(nextCert);
		X509CRL lcr = null;
		if (distPoints.size() != 0) {
			lcr = lcrLoader.get(distPoints, date);
			if (lcr != null) {
				X509CRLEntry entry = lcr.getRevokedCertificate(nextCert
						.getSerialNumber());
				if (entry != null) {
					if (entry.getRevocationDate() != null
							&& entry.getRevocationDate().before(date)) {
						throw new RevokedException();
					}
				}

				if (lcr.getThisUpdate().before(date)) {
					Date upd = lcr.getNextUpdate();
					return new CertStatus(StatusConst.UNKNOWN, upd);
				}
				Date upd = lcr.getNextUpdate();
				return new CertStatus(StatusConst.GOOD, upd);
			}
			else {
				LOG.error("LCR is NULL");
				return new CertStatus(StatusConst.UNTRUSTED, null);
			}
		} else {
			LOG.error("CRL DP not found");
			return new CertStatus(StatusConst.UNKNOWN, null);
		}
	}
}
