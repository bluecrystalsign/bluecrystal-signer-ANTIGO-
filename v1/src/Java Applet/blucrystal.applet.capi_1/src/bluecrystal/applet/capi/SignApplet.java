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

import java.awt.Graphics;

public class SignApplet extends java.applet.Applet implements SignCapiApplet {
	private static final long serialVersionUID = 1L;
	private String msg;
	private boolean active = false;
	private CapiSignService svc;
	
	
	public String getMsg() {
		return msg;
	}

	public boolean isActive() {
		return active;
	}

	@Override
	public void destroy() {
		msg = "destroy";
		super.destroy();
		svc.destroy();
		
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
		try {
			super.init();
			System.out.println("iniciando Applet CAPI de 2015.08.18...");

			svc = new CapiSignService();
			
			svc.init();
			//getCertificate("title", "message", "", "");
			msg = "init";
			active = true;
		} catch (Throwable e) {
			e.printStackTrace();
			msg = e.getLocalizedMessage();
			active = false;
		}

	}
	public void paint(Graphics g) {

		g.drawString(msg, 50, 25);
	}

	@Override
	public String getCertificate(String title, String message, String subjectRegex,
			String issuerRegex) {
		try {
			return svc.getCertificate(title, message, subjectRegex, issuerRegex);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "ERROR";
	}

	@Override
	public String sign(int alg, String saValue) {
		try {
			String sign = svc.sign(alg, saValue);
			return sign;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "ERROR";
	}

	@Override
	public int getKeySize() {
		try {
			return svc.getKeySize();

		} catch (Exception e) {
			e.printStackTrace();
		}
		return -1;
	}

	@Override
	public String getSubject() {
		try {
			return svc.getSubject();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "ERROR";
	}
	

}
