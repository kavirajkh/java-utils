package com.kaviraj.poc.deadlock;

public class Deadlock {


	
	public static void main(String[] args) {
		
		final Object resource1 = "resource1";
		final Object resource2 = "resource2";
		
		Thread t1 = new Thread() {

			
			public void run() {
				synchronized (resource1) {
					resource1.getClass();
					try {
						System.out.println(resource1.toString());
						Thread.currentThread().sleep(100);
						synchronized (resource2) {
							System.out.println(resource2.toString());
						}
						System.out.println("Thread1 ...");

					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
				
			}
		
		};
		Thread t2 = new Thread(){
				public void run() {
					try {
//					Thread.currentThread().sleep(1000);

					synchronized (resource2) {
						System.out.println(resource2.toString());
					
							Thread.currentThread().sleep(100);

							synchronized (resource1) {
								System.out.println(resource1.toString());
							}
							System.out.println("Thread2 ...");

						} }catch (InterruptedException e) {
							e.printStackTrace();
						}
					}
									
	};
	t1.start();
	t2.start();
	}
}
