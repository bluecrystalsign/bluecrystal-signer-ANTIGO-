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



package bluecrystal.service.loader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LCRLoaderImpl implements LCRLoader {
	static final Logger LOG = LoggerFactory.getLogger(LCRLoaderImpl.class);

	
	public LCRLoaderImpl() {
		super();
	}
	Map<String, X509CRL> cache = new HashMap<String, X509CRL>();
	
	public X509CRL get(byte[] dists, Date date) throws CertificateException, CRLException, IOException {
		String url = new String(dists);
		return get(url, date);
	}
	
	public X509CRL get(List<String> dists, Date date) throws CertificateException, CRLException, IOException{
		for( String nextDist : dists){
			try {
				LOG.debug("Buscando: "+ nextDist);

				return get(nextDist, date);
			} catch (IOException e) {
				LOG.error("Could not load CRL ", e);
			}
		}
		return null;
		
	}
	private X509CRL get(String dists, Date date) throws CertificateException, CRLException, IOException {
		String url = new String(dists);
		X509CRL ret = null;
		if( checkInCache(url, date)){
			LOG.debug(":: LCR encontrada no cache: "+url);
			ret =  getInCache(url);
		}else{
			LOG.debug(":: LCR tentando baixar : "+url);
			X509CRL crl = getFresh(url);
			LOG.debug(":: LCR carregada de: "+url);
			if(crl != null){
				addToCache(url, crl);
			}
			ret = crl;
		}

		LOG.debug(":: X509CRL get: "+ret);
		return ret;
		
	}	


	private void addToCache(String key, X509CRL crl) {
		cache.put(key, crl);
		
	}
	private X509CRL getFresh(String url) throws CertificateException, CRLException, IOException {
		byte [] encoded = getFromServer(url);
		return decode(encoded);
	}
	private X509CRL decode(byte[] encoded) throws CertificateException, IOException, CRLException {
		InputStream inStream = new ByteArrayInputStream(encoded);
		CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		 X509CRL crl = (X509CRL)cf.generateCRL(inStream);
		 inStream.close();
		 return crl;
	}
	private byte[] getFromServer(String url) throws MalformedURLException, IOException {
		return ExternalLoaderHttp.getfromUrl(url);
	}
	private X509CRL getInCache(String url) {
		return cache.get(url);
	}
	private boolean checkInCache(String url, Date date) {
		if( cache.containsKey(url)){
			X509CRL cachedCRL = cache.get(url);
			if(cachedCRL.getNextUpdate().after(date)){
				return true;
			}
		}
		return false;
	}

}
