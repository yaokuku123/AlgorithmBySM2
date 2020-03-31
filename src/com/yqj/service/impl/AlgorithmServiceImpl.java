package com.yqj.service.impl;

import com.yqj.Algorithm.SM2;
import com.yqj.Algorithm.SM2KeyPair;
import com.yqj.service.AlgorithmService;
import com.yqj.util.HexUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class AlgorithmServiceImpl implements AlgorithmService {
    private SM2 sm2 = new SM2();
    @Override
    public List<String> generateKeyPair() {
        //生成密钥对
        SM2KeyPair keyPair = sm2.generateKeyPair();
        ECPoint publicKey = keyPair.getPublicKey();
        BigInteger privateKey = keyPair.getPrivateKey();

        //类型转换为String
        String strPublicKey = HexUtils.bytes2Hex(publicKey.getEncoded());
        String strPrivateKey = privateKey.toString(16);

        //已list集合的方式返回
        List<String> list = new ArrayList<String>();
        list.add(strPublicKey);
        list.add(strPrivateKey);


        //验证curve是否一致
//        SM2 sm2_e = new SM2();
//        ECPoint ecPoint1 = sm2.getCurve().decodePoint(HexUtils.hex2Bytes(strPublicKey));
//        ECPoint ecPoint2 = sm2_e.getCurve().decodePoint(HexUtils.hex2Bytes(strPublicKey));
//        System.out.println(ecPoint1);
//        System.out.println(ecPoint2);

        //验证类型还原是否正确
//        System.out.println("----------原始--------------");
//        System.out.println(publicKey);
//        System.out.println(privateKey);
//        System.out.println("----------转换为String--------------");
//        System.out.println(strPublicKey);
//        System.out.println(strPrivateKey);
//        ECPoint newPublicKey = sm2.getCurve().decodePoint(HexUtils.hex2Bytes(publicKey));
//        BigInteger newPrivateKey = new BigInteger(strPrivateKey,16);
//        System.out.println("----------原始2--------------");
//        System.out.println(newPublicKey);
//        System.out.println(newPrivateKey);
        return list;
    }

    @Override
    public String encodingByPublicKey(String data,String _publicKey) {
        //转换类型,将string类型转换为ECPoint类型
        ECPoint publicKey = sm2.getCurve().decodePoint(HexUtils.hex2Bytes(_publicKey));
//        BigInteger newPrivateKey = new BigInteger(strPrivateKey,16);

        //加密，生成密文
        //加密的字符串
        if(data == null || "".equals(data)){
            data = "师兄最帅";
        }

        String encryptSentence = null;
        try {
            encryptSentence = HexUtils.bytes2Hex(sm2.encode(data, publicKey));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }


        return encryptSentence;
    }

    @Override
    public String decodingByPrivateKey(String encryptData, String _privateKey) {
        //转换类型
        BigInteger privateKey = new BigInteger(_privateKey,16);
        String decodeSentence = sm2.decode(HexUtils.hex2Bytes(encryptData), privateKey);

        return decodeSentence;
    }
}
