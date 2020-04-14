package com.siebre.util;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class SM2Utils {
	// ���������Կ��
	public static void generateKeyPair() {
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();

		System.out.println("��Կ: " + Util.byteToHex(publicKey.getEncoded()));
		System.out.println("˽Կ: " + Util.byteToHex(privateKey.toByteArray()));
	}

	// ���ݼ���
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
		// C1 C2 C3ƴװ�ɼ����ִ�
		return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);

	}

	// ���ݽ���
	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (encryptedData == null || encryptedData.length == 0) {
			return null;
		}
		// �����ֽ�����ת��Ϊʮ�����Ƶ��ַ��� ���ȱ�ΪencryptedData.length * 2
		String data = Util.byteToHex(encryptedData);
		/***
		 * �ֽ�����ִ� ��C1 = C1��־λ2λ + C1ʵ�岿��128λ = 130�� ��C3 = C3ʵ�岿��64λ = 64�� ��C2 =
		 * encryptedData.length * 2 - C1���� - C2���ȣ�
		 */
		byte[] c1Bytes = Util.hexToByte(data.substring(0, 130));
		int c2Len = encryptedData.length - 97;
		byte[] c2 = Util.hexToByte(data.substring(130, 130 + 2 * c2Len));
		byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len, 194 + 2 * c2Len));

		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);

		// ͨ��C1ʵ���ֽ�������ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);

		// ���ؽ��ܽ��
		return c2;
	}

	public static void main(String[] args) throws Exception {
		// ������Կ��
//		generateKeyPair();
		String encrypt = encrypt("��������");
		System.out.println("����encrypt:" + encrypt);
		String decrypt = decrypt(encrypt);
		System.out.println("����decrypt:" + decrypt);
	}

	/**
	 * ����
	 * 
	 * @throws Exception
	 */
	public static String decrypt(String password) throws Exception {
		// ���ܹ淶��ʽ˽Կ
		String prik = "00CE5A8F6FF46AA7BDB199ACD634C54ECB456F3484FC4812C2ADA70DBF36F90D05";
		String plainText = new String(SM2Utils.decrypt(Util.hexToByte(prik), Util.hexToByte(password)), StandardCharsets.UTF_8);
		return plainText;
	}

	/**
	 * ����
	 * 
	 * @throws Exception
	 */
	public static String encrypt(String password) throws Exception {
		byte[] sourceData = password.getBytes();
		// ���ܹ淶��ʽ��Կ
		String pubk = "044BFDF90A4543A4F2B49395556B1EAAB27F8037CE85DBF5F520755E2A4C7BFBB3D179EA650A7DF7C0CF1341E209328B044ED5FCCCCF0FC2DF28CFD0E89C889392";
		String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData);
		return cipherText;

	}
}