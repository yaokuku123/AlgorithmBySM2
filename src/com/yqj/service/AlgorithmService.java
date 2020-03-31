package com.yqj.service;

import java.util.List;

public interface AlgorithmService {
    /**
     * 功能：产生密钥对
     * @return 返回一组密钥对
     */
    List<String> generateKeyPair();

    /**
     * 功能：使用用户提供的公钥加密数据
     * @param data 待加密的数据
     * @param publicKey 公钥
     * @return 使用公钥加密的密文
     */
    String encodingByPublicKey(String data,String publicKey);

    /**
     * 功能：解密密文
     * @param encryptData 密文序列
     * @param privateKey 私钥
     * @return 明文
     */
    String decodingByPrivateKey(String encryptData,String privateKey);
}
