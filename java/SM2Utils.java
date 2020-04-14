package com.siebre.util;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class SM2Utils {
	// 生成随机秘钥对
	public static void generateKeyPair() {
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();

		System.out.println("公钥: " + Util.byteToHex(publicKey.getEncoded()));
		System.out.println("私钥: " + Util.byteToHex(privateKey.toByteArray()));
	}

	// 数据加密
	public static String encrypt(byte[] publicKey, byte[] data) throws IOException {
		if (publicKey == null || publicKey.length == 0) {
			return null;
		}

		if (data == null || data.length == 0) {
			return null;
		}

		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);

		Cipher cipher = new Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);

		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);

		// System.out.println("C1 " + Util.byteToHex(c1.getEncoded()));
		// System.out.println("C2 " + Util.byteToHex(source));
		// System.out.println("C3 " + Util.byteToHex(c3));
		// C1 C2 C3拼装成加密字串
		return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);

	}

	// 数据解密
	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (encryptedData == null || encryptedData.length == 0) {
			return null;
		}
		// 加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
		String data = Util.byteToHex(encryptedData);
		/***
		 * 分解加密字串 （C1 = C1标志位2位 + C1实体部分128位 = 130） （C3 = C3实体部分64位 = 64） （C2 =
		 * encryptedData.length * 2 - C1长度 - C2长度）
		 */
		byte[] c1Bytes = Util.hexToByte(data.substring(0, 130));
		int c2Len = encryptedData.length - 97;
		byte[] c2 = Util.hexToByte(data.substring(130, 130 + 2 * c2Len));
		byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len, 194 + 2 * c2Len));

		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);

		// 通过C1实体字节来生成ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);

		// 返回解密结果
		return c2;
	}

	public static void main(String[] args) throws Exception {
		// 生成密钥对
//		generateKeyPair();
		String encrypt = encrypt("测试明文");
		System.out.println("加密encrypt:" + encrypt);
		String decrypt = decrypt(encrypt);
		System.out.println("解密decrypt:" + decrypt);
	}

	/**
	 * 解密
	 * 
	 * @throws Exception
	 */
	public static String decrypt(String password) throws Exception {
		// 国密规范正式私钥
		String prik = "00CE5A8F6FF46AA7BDB199ACD634C54ECB456F3484FC4812C2ADA70DBF36F90D05";
		String plainText = new String(SM2Utils.decrypt(Util.hexToByte(prik), Util.hexToByte(password)), StandardCharsets.UTF_8);
		return plainText;
	}

	/**
	 * 加密
	 * 
	 * @throws Exception
	 */
	public static String encrypt(String password) throws Exception {
		byte[] sourceData = password.getBytes();
		// 国密规范正式公钥
		String pubk = "044BFDF90A4543A4F2B49395556B1EAAB27F8037CE85DBF5F520755E2A4C7BFBB3D179EA650A7DF7C0CF1341E209328B044ED5FCCCCF0FC2DF28CFD0E89C889392";
		String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData);
		return cipherText;

	}
}