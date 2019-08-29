package com.kaviraj.application.exception;


public class CryptoException extends Exception{

	private static final long serialVersionUID = 1L;
	public CryptoException() { super(); }
	public CryptoException(String message) { super(message); }
	public CryptoException(String message, Throwable cause) { super(message, cause); }
	public CryptoException(Throwable cause) { super(cause); }


}
