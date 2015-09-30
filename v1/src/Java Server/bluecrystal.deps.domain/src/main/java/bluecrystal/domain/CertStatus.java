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

import java.util.Date;

public class CertStatus {
@Override
	public String toString() {
		return "CertStatus [status=" + status + ", goodUntil=" + goodUntil
				+ "]";
	}
private int status;
private Date goodUntil;

public int getStatus() {
	return status;
}
public void setStatus(int status) {
	this.status = status;
}
public Date getGoodUntil() {
	return goodUntil;
}
public void setGoodUntil(Date goodUntil) {
	this.goodUntil = goodUntil;
}
public CertStatus(int status, Date goodUntil) {
	super();
	this.status = status;
	this.goodUntil = goodUntil;
}

}
