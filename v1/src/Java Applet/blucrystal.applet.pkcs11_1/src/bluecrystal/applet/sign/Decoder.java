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

public class Decoder {
	public static byte[] convHexToByte(String content)  {
		byte[] signbyte;
		content = content.trim();
		String[] signList = splitHex(content);
		signbyte = conv(signList);
		return signbyte;
	}
	
	public static String conv(byte[] byteArray){
		StringBuffer result = new StringBuffer();
		for (byte b:byteArray) {
		    result.append(String.format("%02X", b));
		}
		return result.toString();
	}
	
	private static String[] splitHex(String content) {
		String[] ret = null;
		int len = content.length();
		if(len % 2 == 0){
			ret = new String[len/2];
			for(int i = 0; i < len/2; i++){
				ret[i] = content.substring(i*2, (i+1)*2);
			}
		}
			
		return ret;
	}
	private static byte[] conv(String[] certList) {
		byte[] certbyte = new byte[certList.length];

		for (int i = 0; i < certbyte.length; i++) {
			certbyte[i] = conv(certList[i]);
		}
		return certbyte;
	}
	private static byte conv(String hex) {
		int i = Integer.parseInt(hex, 16);
		byte c = (byte) i;
		return c;
	}
}
