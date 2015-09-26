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
package bluecrystal.applet.capi;

import java.io.File;

import bluecrystal.applet.capi.domain.GetCertificateParms;
import bluecrystal.applet.capi.domain.GetKeySizeParms;
import bluecrystal.applet.capi.domain.GetSignParms;
import bluecrystal.applet.capi.domain.GetSubject;

public class CapiSignService implements SignCapiApplet {
	private static final String SIGNER_CAPI_DLL = "/signerCapi.dll";
	private static final String SIGNER_CAPI_64_DLL = "/signerCapi64.dll";
	
	private static iSignCapi 	INSTANCE = null;
	private MySynch 			mySynch = null;
	private GetCertificateParms getCertificateParms = null;
	private GetSignParms 		getSignParms = null;
	private GetKeySizeParms 	getKeySizeParms = null;
	private GetSubject 			getSubjectParms = null;
	
	public CapiSignService() {
	}

	public void init() {
		INSTANCE = loadDll();
		mySynch = new MySynch();

		createGetCertificateThread();
		createGetKeySizeThread();
		createGetSubjectThread();
		createSignThread();
	}

	public void destroy() {
		INSTANCE = null;
	}

	@Override
	public String getCertificate(String title, String msg, String subjectRegex,
			String issuerRegex) {

		getCertificateParms = new GetCertificateParms(title, msg, subjectRegex,
				issuerRegex);

		mySynch.countDownGetCertificate();

		String ret = "ERROR";
		try {
			mySynch.getEndedGetCertificate();
			ret = getCertificateParms.getRet();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return ret;
	}

	@Override
	public String sign(int alg, String saValue) {
		getSignParms = new GetSignParms(alg, saValue);

		mySynch.countDownSign();

		String ret = "ERROR";
		try {
			mySynch.getEndedSign();
			ret = getSignParms.getRet();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return ret;
	}

	@Override
	public int getKeySize() {
		getKeySizeParms = new GetKeySizeParms();

		mySynch.countDownGetKeySize();

		int ret = -1;
		try {
			mySynch.getEndedGetKeySize();
			ret = getKeySizeParms.getRet();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return ret;
	}

	@Override
	public String getSubject() {
		getSubjectParms = new GetSubject();

		mySynch.countDownGetSubject();

		String ret = "ERROR";
		try {
			mySynch.getEndedGetSubject();
			ret = getSubjectParms.getRet();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return ret;
	}

	private iSignCapi loadDll() {
		LoaderUtil lu = new LoaderUtil();
		
		try {
			File dll = lu.loadFile(SIGNER_CAPI_64_DLL);

			System.out.println("Carregando (64 bits): " + dll.getAbsolutePath());

			
			return lu.loadNative(dll);
		} catch (Throwable e) {
			System.out.println("Problemas carregando (64 bits) "+e.getLocalizedMessage());
			
			
			
			
			try {
				File dll = lu.loadFile(SIGNER_CAPI_DLL);

				System.out.println("Carregando (32 bits): " + dll.getAbsolutePath());

				
				return lu.loadNative(dll);
			} catch (Exception e1) {
				System.out.println("Problemas carregando (32 bits) "+e1.getLocalizedMessage());
				e1.printStackTrace();
			}

		}
		return null;
	}

	private void createGetCertificateThread() {
		Thread javascriptListener = new Thread() {

			public void run() {
				while (true) {
					try {
						mySynch.awaitGetCertificate();
						String certificate = INSTANCE.getCertificate(
								getCertificateParms.getTitle(),
								getCertificateParms.getMsg(),
								getCertificateParms.getSubjectRegex(),
								getCertificateParms.getIssuerRegex());
						getCertificateParms.setRet(certificate);

					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					mySynch.setEndedGetCertificate();
					mySynch.resetGetCertificate();
				}
			}
		};
		javascriptListener.start();

	}

	private void createGetKeySizeThread() {
		Thread javascriptListener = new Thread() {

			public void run() {
				while (true) {
					try {
						mySynch.awaitGetKeySize();
						int size = INSTANCE.getKeySize();
						getKeySizeParms.setRet(size);

					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					mySynch.setEndedGetKeySize();
					mySynch.resetGetKeySize();
				}
			}
		};
		javascriptListener.start();

	}

	private void createSignThread() {
		Thread javascriptListener = new Thread() {

			public void run() {
				while (true) {
					try {
						mySynch.awaitSign();
						String sign = INSTANCE.sign(
								getSignParms.getAlg(), getSignParms.getSaValue());
						getSignParms.setRet(sign);

					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					mySynch.setEndedSign();
					mySynch.resetSign();
				}
			}
		};
		javascriptListener.start();

	}

	private void createGetSubjectThread() {
		Thread javascriptListener = new Thread() {

			public void run() {
				while (true) {
					try {
						mySynch.awaitGetSubject();
						String subject = INSTANCE.getSubject(
									);
						getSubjectParms.setRet(subject);

					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					mySynch.setEndedGetSubject();
					mySynch.resetGetSubject();
				}
			}
		};
		javascriptListener.start();

	}

	@Override
	public String getMsg() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isActive() {
		// TODO Auto-generated method stub
		return false;
	}

}
