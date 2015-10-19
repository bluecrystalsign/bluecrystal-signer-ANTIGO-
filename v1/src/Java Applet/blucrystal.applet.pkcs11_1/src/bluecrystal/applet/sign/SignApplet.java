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

package bluecrystal.applet.sign;

import java.awt.Graphics;
import java.net.URL;
import java.security.Provider;
import java.security.Security;

public class SignApplet extends java.applet.Applet implements SignAppletP11 {
	private static final long serialVersionUID = 1L;
	private String msg;
	private boolean active = false;
	public String getMsg() {
		return msg;
	}

	public boolean isActive() {
		return active;
	}

	private Pkcs11 p11 = null;
	private final MySynch mySynch = new MySynch();

	@Override
	public void destroy() {
		msg = "destroy";
		super.destroy();
	}

	@Override
	public void start() {

		super.start();
	}

	@Override
	public void stop() {
		msg = "stop";
		super.stop();
	}

	/**
	 * 
	 */
	public void init() {
		super.init();
		System.out.println("iniciando Applet PKCS#11 de 2015.08.18...");

		String module = getParameter("module");
		String otherPath = getParameter("otherPath");
		init(module, otherPath);
	}
	public void init(String module, String otherPath) {
		try {
//			msg = "digite o PIN e 'Carregar'...'";
//			URL codebase = getCodeBase();
//			System.out.println("codebase: " + codebase);


//			 System.out.println("PROVIDER: "+Security.getProviders().length);
//			 for(Provider next : Security.getProviders()){
//			 System.out.println(next.getName());
//			 for (String key: next.stringPropertyNames())
//			 System.out.println("\t" + key + "\t" + next.getProperty(key));
//			 }

			p11 = new Pkcs11(module, otherPath);
			createSignThread();
			createLCThread();
			createSymetricKeyThread();

			resize(1, 1);
			super.init();
			msg = "";
			active = true;
		} catch (Exception e) {
			e.printStackTrace();
			msg = e.getLocalizedMessage();
			active = false;
		}

	}

	
	/* (non-Javadoc)
	 * @see bluecrystal.applet.sign.SignAppletP11#sign(int, int, java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public String sign(int store, int alg, String userPIN, String certAlias,
			String orig) {

		String ret = "";
		p11.setUserPIN(userPIN);
		p11.setCertAlias(certAlias);
		p11.setOrig(orig);
		p11.setAlg(alg);
		p11.setStore(store);
		
		System.out.println("*** sign ***");
		System.out.println("userPIN: "+userPIN);
		System.out.println("certAlias: "+certAlias);
		System.out.println("orig: "+orig);
		System.out.println("alg: "+alg);
		System.out.println("store: "+store);
		mySynch.countDown();

		try {
			mySynch.getEnded();
			this.msg = "assinatura realizada";
			ret = p11.getResult();
		} catch (InterruptedException e) {
			this.msg = "problema na assinatura.";
			e.printStackTrace();
		}

		this.repaint();
		if (p11.getLastError().length() != 0) {
			return p11.getLastError();
		}

		return ret;
	}


	/* (non-Javadoc)
	 * @see bluecrystal.applet.sign.SignAppletP11#loadCerts(int, java.lang.String, java.lang.String)
	 */
	@Override
	public String listCerts(int store, String userPIN) {
		try {
			p11.setUserPIN(userPIN);
			p11.setStore(store);
			mySynch.startLC();
			mySynch.awaitLC2();

			String ret = "";

				ret = p11.loadCertsJson();
			if (p11.getLastError() != null && p11.getLastError().length() != 0) {
				return p11.getLastError();
			}
			return ret;

		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return "";

	}

	/* (non-Javadoc)
	 * @see bluecrystal.applet.sign.SignAppletP11#getCert(java.lang.String)
	 */
	@Override
	public String getCertificate(String alias) {
		try {
			String cert = p11.getCert(alias);
			return cert;
		} catch (Throwable e) {
			e.printStackTrace();
		}
		return null;

	}
	
	@Override
	public int getKeySize(String alias) {
		try {
			return p11.getKeySize(alias);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return -1;
	}

	@Override
	public String getSubject(String alias) {
		try {
			return p11.getSubject(alias);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "ERROR";
	}

	
	private void createSignThread() {
		Thread javascriptListener = new Thread() {

			public void run() {
				while (true) {
					try {
						mySynch.await();
						p11.sign();
						System.out.println("assinatura feita");
						mySynch.setEnded();
						mySynch.reset();
					} catch (Exception e) {
						e.printStackTrace();
						System.out.println("*** "+e.getLocalizedMessage());
					}
				}
			}
		};
		javascriptListener.start();
	}

	private void createSymetricKeyThread() {
		Thread javascriptListener = new Thread() {

			public void run() {
				while (true) {
					try {
						mySynch.SKeyAwait();
						p11.skeyDercypt();
					} catch (Exception e) {
						e.printStackTrace();
					}
					mySynch.SKeyEndedCountDown();
					mySynch.SKeyReset();
				}
			}
		};
		javascriptListener.start();
	}

	private void createLCThread() {
		Thread javascriptListener = new Thread() {

			public void run() {
				try {
					while (true) {
						mySynch.awaitLC();
						p11.loadKeyStore();
						p11.refreshCerts();
						mySynch.startLC2();
						mySynch.resetLC();
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		};
		javascriptListener.start();
	}

	public void paint(Graphics g) {

		g.drawString(msg, 50, 25);
	}

	
}