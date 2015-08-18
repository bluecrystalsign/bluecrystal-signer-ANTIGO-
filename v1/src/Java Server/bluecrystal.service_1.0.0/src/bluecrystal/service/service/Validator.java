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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import bluecrystal.domain.NameValue;
import bluecrystal.service.helper.Utils;


public class Validator extends BaseService implements ValidatorSrv {

	@Override
	public NameValue[] parseCertificate(String certificate)
			throws Exception {
			Map<String, String> ret = null;
			ret = parseCertificateAsMap(certificate);
			
			int size = ret.keySet().size();
			NameValue[] retNV = new NameValue[size];
			
			int i = 0;
			for(String next : ret.keySet()){
				
				NameValue nv  = new NameValue(next, ret.get(next));
				retNV[i] = nv;
				i++;
			}
			return retNV;
	}

	@Override
	public Map<String, String> parseCertificateAsMap(String certificate)
			throws Exception {
		Map<String, String> ret;
		X509Certificate cert = Utils.createCert(certificate);
		
		CertificateService certServ = new CertificateService();
		List<X509Certificate> chain = new ArrayList<X509Certificate>();
		chain.add(cert);
		ret = certServ.parseChainAsMap(chain );
		return ret;
	}
}
