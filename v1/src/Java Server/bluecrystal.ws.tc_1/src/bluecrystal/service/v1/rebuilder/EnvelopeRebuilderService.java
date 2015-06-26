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

package bluecrystal.service.v1.rebuilder;

import javax.jws.WebParam;
import javax.jws.WebService;


@WebService
public interface EnvelopeRebuilderService {
	
	public abstract String rebuildEnvelope(
			@WebParam(name = "format")int format,
			@WebParam(name = "envelopeb64")String envelopeb64) throws Exception;

}
