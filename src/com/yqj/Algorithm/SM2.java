package com.yqj.Algorithm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;


import com.yqj.util.HexUtils;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class SM2 {
	
	private static ECPoint G;
	private static boolean debug = false;
	private  ECCurve.Fp curve;
	private static final int DIGEST_LENGTH = 32;
	
	private static ECDomainParameters ecc_bc_spec;
	private static BigInteger n = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "7203DF6B" + "21C6052B" + "53BBF409" + "39D54123", 16);
	private static BigInteger p = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFF", 16);
	private static BigInteger a = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFC", 16);
	private static BigInteger b = new BigInteger(
			"28E9FA9E" + "9D9F5E34" + "4D5A9E4B" + "CF6509A7" + "F39789F5" + "15AB8F92" + "DDBCBD41" + "4D940E93", 16);
	private static BigInteger gx = new BigInteger(
			"32C4AE2C" + "1F198119" + "5F990446" + "6A39C994" + "8FE30BBF" + "F2660BE1" + "715A4589" + "334C74C7", 16);
	private static BigInteger gy = new BigInteger(
			"BC3736A2" + "F4F6779C" + "59BDCEE3" + "6B692153" + "D0A9877C" + "C62A4740" + "02DF32E5" + "2139F0A0", 16);
	public SM2() {
		curve = new ECCurve.Fp(p, // q
				a, // a
				b); // b
		G = curve.createPoint(gx, gy ,false);
		ecc_bc_spec = new ECDomainParameters(curve, G, n);
	}

	//此处做了修改，增加了一个getter方法---姚
	public ECCurve.Fp getCurve() {
		return curve;
	}

	private static boolean checkPublicKey(ECPoint publicKey) {

		if (!publicKey.isInfinity()) {

			BigInteger x = publicKey.getX().toBigInteger();
			BigInteger y = publicKey.getY().toBigInteger();

			if (between(x, new BigInteger("0"), p) && between(y, new BigInteger("0"), p)) {

				BigInteger xResult = x.pow(3).add(a.multiply(x)).add(b).mod(p);

				if (debug)
					System.out.println("xResult: " + xResult.toString());

				BigInteger yResult = y.pow(2).mod(p);

				if (debug)
					System.out.println("yResult: " + yResult.toString());

				if (yResult.equals(xResult) && publicKey.multiply(n).isInfinity()) {
					return true;
				}
			}
		}
		return false;
	}
	
	private static boolean between(BigInteger param, BigInteger min, BigInteger max) {
		if (param.compareTo(min) >= 0 && param.compareTo(max) < 0) {
			return true;
		} else {
			return false;
		}
	}
	
	private static byte[] KDF(byte[] Z, int klen) {
		int ct = 1;
		int end = (int) Math.ceil(klen * 1.0 / 32);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			for (int i = 1; i < end; i++) {
				baos.write(sm3hash(Z, SM3.toByteArray(ct)));
				ct++;
			}
			byte[] last = sm3hash(Z, SM3.toByteArray(ct));
			if (klen % 32 == 0) {
				baos.write(last);
			} else
				baos.write(last, 0, klen % 32);
			return baos.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static BigInteger randomgenerator(BigInteger max) {
		Random random = new Random();
		BigInteger r = new BigInteger(256, random);
		// int count = 1;

		while (r.compareTo(max) >= 0) {
			r = new BigInteger(128, random);
			// count++;
		}

		// System.out.println("count: " + count);
		return r;
	}
	
	private static byte[] sm3hash(byte[]... params) {
		byte[] res = null;
		try {
			res = SM3.hash(join(params));
		} catch (IOException e) {
			//  Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}
	private static byte[] join(byte[]... params) {//pinjie
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] res = null;
		try {
			for (int i = 0; i < params.length; i++) {
				baos.write(params[i]);
			}
			res = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}
	
	public static void printHexString(byte[] b) {
		for (int i = 0; i < b.length; i++) {
			String hex = Integer.toHexString(b[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			System.out.print(hex.toUpperCase());
		}
		System.out.println();
	}
	
	private boolean allZero(byte[] buffer) {
		for (int i = 0; i < buffer.length; i++) {
			if (buffer[i] != 0)
				return false;
		}
		return true;
	}
	
	public SM2KeyPair generateKeyPair() {

		BigInteger d = randomgenerator(n.subtract(new BigInteger("1")));

		SM2KeyPair keyPair = new SM2KeyPair(G.multiply(d), d);

		if (checkPublicKey(keyPair.getPublicKey())) {
			if (debug)
				System.out.println("密钥对生成成功！");
			return keyPair;
		} else {
			if (debug)
				System.err.println("失败");
			return null;
		}
	}

	public byte[] encode(String input, ECPoint publicKey) throws UnsupportedEncodingException {
		byte[] inputBuffer = input.getBytes("UTF-8");
		if(debug)
		{
			System.out.print("publicKey.Hex = ");
			printHexString(inputBuffer);
		}
		int klen = inputBuffer.length;//示要获得的密钥数据的位长，要求该值小于(2^32-1)*v；
		byte[] C1Buffer;
		ECPoint kpb;
		byte[] t;
		//密钥派生
    	//int v = 256;	//SM2算法目前版本中v只取为256
		
    	
    do{
    	//A1:用随机数发生器产生随机数
    	BigInteger k = randomgenerator(n);//
    	if(debug)
    	{
    		System.out.print("k  = ");
			printHexString(k.toByteArray());
    	}
    	//A2:计算椭圆曲线点C1=[k]G=(x1,y1)，将C1的数据类型转换为比特串；
    	ECPoint C1 =   G.multiply(k);//
    	C1Buffer =  C1.getEncoded();
    	if (debug) {
			System.out.print("C1 = ");
			printHexString(C1Buffer);
		}
		
    	//A3:计算椭圆曲线点S=[h]PB，若s是无穷远点，则报错并退出；
		BigInteger h = ecc_bc_spec.getH();
		if (h != null) {
			ECPoint S =  publicKey.multiply(h);//multiply(h);
			if (S.isInfinity())
				throw new IllegalStateException();
		}
		
    	//A4:计算椭圆曲线点[k]Pb=(x2,y2)，将坐标x2,y2的数据类型转换为比特串；
		kpb =  publicKey.multiply(k);//
    	byte[] kpbBytes =  kpb.getEncoded();
    	
    	//A5:计算t=KDF(x2||y2，klen)，若t为全0比特串，则返回A1；
		t = KDF(kpbBytes, klen);
		if(debug)
		{
			System.out.print("t  = ");
			printHexString(t);
		}
	}while(allZero(t));
		
    	//A6:计算C2=M ⊕ t；异或,M明文
    	byte[] C2 = new byte[klen];
		for (int i = 0; i < klen; i++) {
			C2[i] = (byte) (inputBuffer[i] ^ t[i]);
		}
		if(debug)
		{
			System.out.print("C2 = ");
			printHexString(C2);
		}
    	//A7:计算C3=Hash(x2||M||y2);
		byte[] C3 = sm3hash(kpb.getX().toBigInteger().toByteArray(),inputBuffer,
				kpb.getY().toBigInteger().toByteArray());
		if(debug)
		{
			System.out.print("C3 = ");
			printHexString(C3);
		}
    	//A8:输出密文C=C1||C3||C2．
		byte[] encodeResult = new byte[C1Buffer.length + C2.length + C3.length];

		System.arraycopy(C1Buffer, 0, encodeResult, 0, C1Buffer.length);
		System.arraycopy(C2, 0, encodeResult, C1Buffer.length, C2.length);
		System.arraycopy(C3, 0, encodeResult, C1Buffer.length + C2.length, C3.length);
		
		
		return encodeResult;
	}
	
	public String decode(byte[] encodeData, BigInteger privateKey) {
		
		//B1:从C中取出比特串C1，将C1的数据类型转换为椭圆曲线上的点，验证C1是否满足椭圆曲线方程，若不满足则报错并退出；
		byte[] C1Byte= new byte[65];
		System.arraycopy(encodeData, 0, C1Byte, 0, C1Byte.length);
		ECPoint C1 = curve.decodePoint(C1Byte);
		byte[] C1Buffer;
		C1Buffer =  C1.getEncoded();
		if(debug)
		{
			System.out.print("C1 = ");
			printHexString(C1Buffer);
		}
		
		
		//B2:计算椭圆曲线点S=[h]C1，若S是无穷远点，则报错并退出；
		BigInteger h = ecc_bc_spec.getH();
		if (h != null) {
			ECPoint S = C1.multiply(h);
			if (S.isInfinity())
				throw new IllegalStateException();
		}
		
		
		//B3:计算[db]C1=(x2，y2)，将坐标x2，y2的数据类型转换为比特串；
		ECPoint dBC1 = C1.multiply(privateKey);
		byte[] dBC1Bytes = dBC1.getEncoded();
		
		
		//B4:计算t=KDF(x2||y2,klen)，若t为全0比特串，则报错并退出；
		int klen = encodeData.length - 65 - DIGEST_LENGTH;
		byte[] t = KDF(dBC1Bytes, klen);
		if(debug)
		{
			System.out.print("t  = ");
			printHexString(t);
		}
		
		//B5:从C中取出比特串C2，计算M'=C2⊕t；
		byte[] M = new byte[klen];

		//此处做了修改---姚
		//byte[] C2 = new byte[30];
		byte[] C2 = new byte[klen];
		System.arraycopy(encodeData, 65, C2, 0, klen);
		for (int i = 0; i < M.length; i++) {
			M[i] = (byte) ( C2[i]^ t[i]);//encodeData[C1Byte.length + i]
		}
		if(debug)
		{
			System.out.print("C2 = ");
			printHexString(C2);
			System.out.print("M' = ");
			printHexString(M);
		}
		
		
		//B6:计算u=Hash(x2||M'||y2)，从C中取出比特串C3，若u≠C3，则报错并退出；
		byte[] C3 = new byte[DIGEST_LENGTH];
		System.arraycopy(encodeData, encodeData.length - DIGEST_LENGTH, C3, 0, DIGEST_LENGTH);
		byte[] u = sm3hash(dBC1.getX().toBigInteger().toByteArray(), M,
				dBC1.getY().toBigInteger().toByteArray());
		if (Arrays.equals(u, C3)) {
			if (debug)
				System.out.println("解密成功");
			try {
				return new String(M, "UTF8");//B7:输出明文M'
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			return null;
		} else {
			if (debug) {
				System.out.print("u  = ");
				printHexString(u);
				System.out.print("C3 = ");
				printHexString(C3);
				System.err.println("解密验证失败");
			}
			return null;
		}
		
	}
	public static void main(String[] args) throws UnsupportedEncodingException {
		
		System.out.println("-----------------密钥生成-----------------");
		 // 用户自己主私钥,用户自己设置
		SM2 sm2 = new SM2();
		SM2KeyPair keyPair = sm2.generateKeyPair();
		ECPoint publicKey = keyPair.getPublicKey();
		BigInteger privateKey = keyPair.getPrivateKey();
	
		System.out.println("privateKey = " + privateKey);
		System.out.println("publicKey = " + publicKey);
		System.out.println("-----------------公钥加密-----------------");
		
		
		byte[] data = sm2.encode("测试加密aaaaaaaaaaa123aabb", publicKey);
		System.out.print("密文 = ");
		SM2.printHexString(data);
		System.out.println("-----------------私钥解密-----------------");
		System.out.println("解密后明文:" + sm2.decode(data, privateKey));
	
	}


	//此处加了测试---姚
	@Test
	public void test() throws UnsupportedEncodingException {
		SM2 sm2 = new SM2();
		SM2KeyPair keyPair = sm2.generateKeyPair();
		ECPoint publicKey = keyPair.getPublicKey();
		BigInteger privateKey = keyPair.getPrivateKey();

		String strPublicKey = HexUtils.bytes2Hex(publicKey.getEncoded());
		String strPrivateKey = privateKey.toString(16);

		//加密
		publicKey = sm2.getCurve().decodePoint(HexUtils.hex2Bytes("0406ed75e69d2af7bf5f947abb4f4d822627f14d8b55749a0d52c0b3b16e8cee16ad61702bbbe15dc749be074ed5642c3e56b69500ff01a7b8da9785c0dea57d1e"));

		String data = "你好";
		String encryptSentence = HexUtils.bytes2Hex(sm2.encode(data, publicKey));
		//解密
		privateKey = new BigInteger("ae320066415aa2533c7d6047f977be9e01e05e19bfec48c1104570bcb55d907a",16);
		String decodeSentence1 = sm2.decode(HexUtils.hex2Bytes(encryptSentence), privateKey);
		System.out.println(decodeSentence1);

		SM2 sm2_s = new SM2();
		publicKey = sm2_s.getCurve().decodePoint(HexUtils.hex2Bytes("0406ed75e69d2af7bf5f947abb4f4d822627f14d8b55749a0d52c0b3b16e8cee16ad61702bbbe15dc749be074ed5642c3e56b69500ff01a7b8da9785c0dea57d1e"));
		encryptSentence = HexUtils.bytes2Hex(sm2.encode(data, publicKey));
		String decodeSentence2 = sm2_s.decode(HexUtils.hex2Bytes(encryptSentence), privateKey);
		System.out.println(decodeSentence2);
	}
	
}
