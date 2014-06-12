import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class test {
	private static String key = "buzhidao";
	private static String content = "abcdabcdabcdabcd";// 长度必须是128Bit也就是16字节的倍数，否则sms4无法解密

	public static void main(String[] args) throws Exception {
		System.out.println("---------AES----------");
		AES aes = new AES(getRawKey(key.getBytes()));
		System.out.println("秘钥 "+new String(key));
		System.out.println("明文 "+new String(content));
		byte[] encryptResult = aes.encrypt(content.getBytes());
		String encryptResultStr = parseByte2HexStr(encryptResult);
		System.out.println("加密后原始数组:");
		aes.print(encryptResult);
		System.out.println("加密后：" + encryptResultStr);
		System.out.println("解密后：" + new String(aes.decrypt(encryptResult)));
		// test.printKey(test.decrypt(test.encrypt(content.getBytes())));
		
		System.out.println("---------SMS4----------");
		SMS4 sms4 = new SMS4(getRawKey(key.getBytes()));
		System.out.println("秘钥 "+new String(key));
		System.out.println("明文 "+new String(content));
		byte[] encryptResult1 = sms4.encrypt(content.getBytes());
		String encryptResultStr1 = parseByte2HexStr(encryptResult1);
		System.out.println("加密后原始数组:");
		sms4.print(encryptResult1);
		System.out.println("加密后：" + encryptResultStr1);
		System.out.println("解密后：" + new String(sms4.decrypt(parseHexStr2Byte("24A419F8FEDA3E18C88AF00E5254BF25"))));
	}

	private static byte[] getRawKey(byte[] seed) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecureRandom sr = null;
		sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);
		kgen.init(128, sr); // 192 and 256 bits may not be available
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		return raw;
	}

	public static String parseByte2HexStr(byte buf[]) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; i++) {
			String hex = Integer.toHexString(buf[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}

	public static byte[] parseHexStr2Byte(String hexStr) {
		if (hexStr.length() < 1)
			return null;
		byte[] result = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexStr.length() / 2; i++) {
			int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),
					16);
			result[i] = (byte) (high * 16 + low);
		}
		return result;
	}
	public static byte[] toByte(String hexString) {
		int len = hexString.length() / 2;
		byte[] result = new byte[len];
		for (int i = 0; i < len; i++)
			result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2),
					16).byteValue();
		return result;
	}
}
