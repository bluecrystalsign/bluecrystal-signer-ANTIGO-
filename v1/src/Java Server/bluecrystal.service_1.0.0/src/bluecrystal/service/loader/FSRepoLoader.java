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

package bluecrystal.service.loader;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import bluecrystal.service.interfaces.RepoLoader;

public class FSRepoLoader implements RepoLoader {
	
	private String certFolder = Messages.getString("FSRepoLoader.certFolder"); //$NON-NLS-1$
//	static final Logger logger = LoggerFactory.getLogger(FSRepoLoader.class);

	@Override
	public InputStream load(String key) throws Exception {
		FileInputStream fis = null;
			fis = new FileInputStream(getFullPath(key));
		return fis;
	}

	@Override
	public InputStream loadFromContent(String key) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String Put(InputStream input, String key) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String PutInSupport(InputStream input, String key) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String PutInContent(InputStream input, String key) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String checkContentByHash(String sha256) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String PutIn(InputStream input, String key, String bucket) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String PutDirect(InputStream input, String key, String bucket) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String createAuthUrl(String object) throws Exception {
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public boolean isDir(String object) throws Exception {
		File f = new File (getFullPath(object));
		return f.isDirectory();
	}

	@Override
	public String getFullPath(String object) {
		return certFolder + File.separator+ object;
	}
	
	@Override
	public boolean exists(String object) throws Exception {
		File f = new File (getFullPath(object));
		return f.exists();
	}
	
	

	@Override
	public String[] list(String object) throws Exception {
		File f = new File (getFullPath(object));
		String[] fList = f.list();
		
		String[] ret = new String[fList.length];
		
		for(int i =0; i < fList.length; i++ ){
			ret[i] = object + File.separator + fList[i];
		}
		
		return ret;	}

}
