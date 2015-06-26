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

public class StatusConst {
	public final static int GOOD = 0;
	public final static int UNKNOWN = 1;
	public final static int EXPIRED = 2;
	public final static int PATH_ERROR = 3;
	public final static int PROCESSING_ERROR = 4;
	public final static int REVOKED = 100;
	public final static int KEYCOMPROMISE = 101;
	public final static int CACOMPROMISE = 102;
	public final static int AFFILIATIONCHANGED = 103;
	public final static int SUPERSEDED = 104;
	public final static int CESSATIONOFOPERATION = 105;
	public final static int CERTIFICATEHOLD = 106;
	public final static int REMOVEFROMCRL = 108;
	public final static int PRIVILEGEWITHDRAWN = 109;
	public final static int AACOMPROMISE = 110;
	public final static int UNSABLEKEY = 1000;
	public final static int UNTRUSTED = 1001;
	public final static int LAST_STATUS = UNTRUSTED;
}
