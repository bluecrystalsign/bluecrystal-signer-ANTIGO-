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

package bluecrystal.example.web.util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.GregorianCalendar;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

public class Convert {
	public static byte[] readFile(String destPathname) throws Exception {
		InputStream is = new FileInputStream(destPathname);
		byte[] b = new byte[is.available()];
		is.read(b);
		is.close();
		return b;
	}
	
	public static XMLGregorianCalendar asXMLGregorianCalendar(java.util.Date date) throws DatatypeConfigurationException {
        if (date == null) {
        	return null;
        } else {
            GregorianCalendar gc = new GregorianCalendar();
            gc.setTimeInMillis(date.getTime());
            return DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
        }
    }
}
