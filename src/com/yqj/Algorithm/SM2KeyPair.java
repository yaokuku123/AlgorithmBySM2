package com.yqj.Algorithm;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class SM2KeyPair {

	private final ECPoint publicKey;
	private final BigInteger privateKey;

	SM2KeyPair(ECPoint publicKey, BigInteger privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public ECPoint getPublicKey() {
		return publicKey;
	}

	public BigInteger getPrivateKey() {
		return privateKey;
	}

	@Override
	public String toString() {
		return "SM2KeyPair{" +
				"publicKey=" + publicKey +
				", privateKey=" + privateKey +
				'}';
	}
}
