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

import java.util.concurrent.CountDownLatch;

public class MySynch {
	CountDownLatch goSign = new CountDownLatch(1);
	CountDownLatch isEnded = new CountDownLatch(1);
	CountDownLatch loadCerts = new CountDownLatch(1);
	CountDownLatch loadCerts2 = new CountDownLatch(1);
	CountDownLatch symKey = new CountDownLatch(1);
	CountDownLatch symKeyEnded = new CountDownLatch(1);

	public void countDown() {
		goSign.countDown();
	}

	public void await() throws InterruptedException {
		goSign.await();
	}
	
	public void reset() {
		goSign = new CountDownLatch(1);
		isEnded = new CountDownLatch(1);
	}

	public void setEnded() {
		isEnded.countDown();		
	}

	public void getEnded() throws InterruptedException {
		isEnded.await();
	}
	
	public void startLC() {
		loadCerts.countDown();
	}

	public void awaitLC() throws InterruptedException {
		loadCerts.await();
	}
	
	public void resetLC() {
		loadCerts = new CountDownLatch(1);
		loadCerts2 = new CountDownLatch(1);
	}
	public void startLC2() {
		loadCerts2.countDown();
	}

	public void awaitLC2() throws InterruptedException {
		loadCerts2.await();
	}

	public void SKeyCountDown() {
		System.out.println("SKeyCountDown: "+symKey.getCount());
		symKey.countDown();
	}

	public void SKeyAwait() throws InterruptedException {
		System.out.println("SKeyAwait: "+symKey.getCount());
		symKey.await();
	}
	
	public void SKeyReset() {
		System.out.println("SKeyReset");
		System.out.println(symKey.getCount());
		System.out.println(symKeyEnded.getCount());
		symKey = new CountDownLatch(1);
		symKeyEnded = new CountDownLatch(1);
	}
	
	public void SKeyEndedCountDown() {
		System.out.println("SKeyEndedCountDown: "+symKeyEnded.getCount());
		symKeyEnded.countDown();
	}

	public void SKeyEndedAwait() throws InterruptedException {
		System.out.println("SKeyEndedAwait: "+symKeyEnded.getCount());
		symKeyEnded.await();
	}
	

}
