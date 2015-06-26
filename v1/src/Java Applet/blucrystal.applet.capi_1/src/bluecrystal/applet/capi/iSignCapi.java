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

import com.sun.jna.Library;

public interface iSignCapi extends Library {
//	void doPrintIt();
	String getCertificate(String title,
			String msg, 
			String subjectRegex, String issuerRegex);
	
	String sign(int alg, String saValue);
	
	int getKeySize();
	String getSubject();
	
}
