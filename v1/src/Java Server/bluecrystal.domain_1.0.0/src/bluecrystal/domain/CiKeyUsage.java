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

package bluecrystal.domain;

//KeyUsage ::= BIT STRING {
//digitalSignature        (0),
//nonRepudiation          (1),
//keyEncipherment         (2),
//dataEncipherment        (3),
//keyAgreement            (4),
//keyCertSign             (5),
//cRLSign                 (6),
//encipherOnly            (7),
//decipherOnly            (8) }	

public class CiKeyUsage {
	public final static int digitalSignature 	= 0;
	public final static int nonRepudiation 		= 1;
	public final static int keyEncipherment 	= 2;
	public final static int dataEncipherment 	= 3;
	public final static int keyAgreement		= 4;
	public final static int keyCertSign			= 5;
	public final static int cRLSign				= 6;
	public final static int encipherOnly		= 7;
	public final static int decipherOnly		= 8;
	public final static int length				= decipherOnly+1;
}
