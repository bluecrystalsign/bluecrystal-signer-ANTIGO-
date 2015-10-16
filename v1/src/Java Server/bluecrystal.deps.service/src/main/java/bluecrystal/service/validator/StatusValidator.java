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
import java.util.List;

import bluecrystal.domain.CertStatus;
import bluecrystal.service.exception.RevokedException;
import bluecrystal.service.exception.UndefStateException;

public interface StatusValidator {
	public void setUseOcsp(boolean useOcsp);
	public CertStatus verifyStatus(Collection<X509Certificate> certsOnPath, Date date)
	throws IOException, CertificateException, CRLException,
	UndefStateException, RevokedException;	
	public CertStatus verifyStatusEE(Collection<X509Certificate> certsOnPath, Date date, List<String> crlDist)	throws IOException, CertificateException, CRLException,
	UndefStateException, RevokedException;	
}