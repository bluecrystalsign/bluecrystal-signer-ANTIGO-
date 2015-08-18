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

package bluecrystal.service.interfaces;

import java.io.InputStream;

public interface RepoLoader {

	public abstract InputStream load(String key) throws Exception;

	public abstract InputStream loadFromContent(String key);

	public abstract String Put(InputStream input, String key);

	public abstract String PutInSupport(InputStream input, String key);

	public abstract String PutInContent(InputStream input, String key);

	public abstract String checkContentByHash(String sha256);

	public abstract String PutIn(InputStream input, String key, String bucket);

	public abstract String PutDirect(InputStream input, String key,
			String bucket);
	public abstract String createAuthUrl(String object) throws Exception;
	
	public abstract boolean isDir(String object) throws Exception;

	String[] list(String object) throws Exception;

	boolean exists(String object) throws Exception;

	String getFullPath(String object);

}