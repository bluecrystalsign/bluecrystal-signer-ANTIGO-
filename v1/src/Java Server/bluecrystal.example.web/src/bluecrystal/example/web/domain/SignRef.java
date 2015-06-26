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

package bluecrystal.example.web.domain;

public class SignRef {
	private String hash_value;
	private long time_value;
	private String sa_value;
	public SignRef(String hash_value, long time_value, String sa_value) {
		super();
		this.hash_value = hash_value;
		this.time_value = time_value;
		this.sa_value = sa_value;
	}
	public String getHash_value() {
		return hash_value;
	}
	public void setHash_value(String hash_value) {
		this.hash_value = hash_value;
	}
	public long getTime_value() {
		return time_value;
	}
	public void setTime_value(long time_value) {
		this.time_value = time_value;
	}
	public String getSa_value() {
		return sa_value;
	}
	public void setSa_value(String sa_value) {
		this.sa_value = sa_value;
	}

}
