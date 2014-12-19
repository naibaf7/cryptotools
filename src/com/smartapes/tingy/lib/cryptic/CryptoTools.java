package com.smartapes.tingy.lib.cryptic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.smartapes.tingy.lib.cryptic.CryptoTools.CryptoInfo;

/**
 * Attention! This requires Java Unlimited Strength Cryptocraphy Policy!! http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html See
 * the download's readme file on how to do it!
 * 
 * @author Fabian David Tschopp
 *
 */
public class CryptoTools {

	/**
	 * AES-SHA1PRNG AES-256bit key to be used as one-time session key.
	 * 
	 * @return Key as hex encoded string.
	 */
	public static String randomSessionKey() {
		// Symmetric shared key (client chosen)
		String key = null;
		try {
			KeyGenerator keyGenerator;
			keyGenerator = KeyGenerator.getInstance("AES");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(System.currentTimeMillis() * System.nanoTime());
			keyGenerator.init(256, random);
			Key symkey = keyGenerator.generateKey();
			byte[] keybytes = symkey.getEncoded();
			key = keyToHexString(keybytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return key;
	}

	/**
	 * Decodes the AES key with a RSA private key.
	 * 
	 * @param in
	 *            CryptoInfo object with private key and data (encrypted) set. Data can be incomplete.
	 * @return CryptoInfo object with private key and session key set.
	 */
	public static CryptoInfo decodeRSAKeyOnly(CryptoInfo in) {
		CryptoInfo out = null;
		try {
			// Asymmetric private key
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(hexToByte(in.getPrivateHexKey()));
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PrivateKey priv = fact.generatePrivate(keySpec);

			ByteArrayInputStream bais = new ByteArrayInputStream(in.getData());
			byte[] encoded = new byte[256];
			bais.read(encoded);

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, priv);
			byte[] decoded = cipher.doFinal(encoded);
			out = new CryptoInfo();
			out.setSessionHexKey(keyToHexString(decoded));
			out.setPrivateHexKey(in.getPrivateHexKey());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return out;
	}

	/**
	 * Encodes a byte buffer with a RSA public key and a AES session key.
	 * 
	 * @param in
	 *            CryptoInfo object with public key, session key and data (decrypted) set.
	 * @return CryptoInfo object with private key, session key and data (encrypted) set.
	 */
	public static CryptoInfo encodeRSAAES(CryptoInfo in) {
		CryptoInfo out = null;
		try {
			// Asymmetric public key
			X509EncodedKeySpec spec = new X509EncodedKeySpec(hexToByte(in.publicHexKey));
			KeyFactory keyFactory;
			keyFactory = KeyFactory.getInstance("RSA");
			PublicKey key = keyFactory.generatePublic(spec);

			// Encrypt symmetric shared key
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encoded = cipher.doFinal(hexToByte(in.getSessionHexKey()));

			// Do AES data encryption
			CryptoInfo inter = new CryptoInfo();
			inter.setData(in.getData());
			inter.setSessionHexKey(in.getSessionHexKey());
			inter = encodeAES(inter);

			// Write out the encrypted key and data
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			baos.write(encoded);
			baos.write(inter.getData());
			baos.flush();
			baos.close();
			out = new CryptoInfo();
			out.setData(baos.toByteArray());
			out.setPublicHexKey(in.publicHexKey);
			out.setSessionHexKey(in.sessionHexKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return out;
	}

	/**
	 * Decodes a byte buffer with a RSA private key.
	 * 
	 * @param in
	 *            CryptoInfo object with private key and data (encrypted) set.
	 * @return CryptoInfo object with private key, session key and data (decrypted) set.
	 */
	public static CryptoInfo decodeRSAAES(CryptoInfo in) {
		CryptoInfo out = null;
		try {
			// Asymmetric private key
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(hexToByte(in.getPrivateHexKey()));
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PrivateKey priv = fact.generatePrivate(keySpec);

			ByteArrayInputStream bais = new ByteArrayInputStream(in.getData());
			byte[] encoded = new byte[256];
			bais.read(encoded);

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, priv);
			byte[] decoded = cipher.doFinal(encoded);

			// Do AES data decryption
			CryptoInfo inter = new CryptoInfo();
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] bdata = new byte[1024];
			int read;
			while ((read = bais.read(bdata)) != -1) {
				baos.write(bdata, 0, read);
			}
			bais.close();
			baos.flush();
			baos.close();
			inter.setData(baos.toByteArray());
			inter.setSessionHexKey(keyToHexString(decoded));
			inter = decodeAES(inter);

			out = new CryptoInfo();
			out.setData(inter.getData());
			out.setPrivateHexKey(in.getPrivateHexKey());
			out.setSessionHexKey(inter.getSessionHexKey());

		} catch (Exception e) {
			e.printStackTrace();
		}
		return out;
	}

	/**
	 * Encodes a byte buffer with a AES session key.
	 * 
	 * @param in
	 *            CryptoInfo object with session key and data (decrypted) set.
	 * @return CryptoInfo object with session key and data (encrypted) set.
	 */
	public static CryptoInfo encodeAES(CryptoInfo in) {
		CryptoInfo out = null;
		try {
			// Generate IV
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(System.currentTimeMillis() * System.nanoTime());
			byte[] iv = new byte[16];
			random.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			baos.write(iv);
			Cipher symmetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			symmetricCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(hexToByte(in.getSessionHexKey()), "AES"), ivspec);
			CipherOutputStream cos = new CipherOutputStream(baos, symmetricCipher);

			cos.write(in.getData());
			cos.flush();
			baos.flush();
			cos.close();

			out = new CryptoInfo();
			out.setData(baos.toByteArray());
			out.setSessionHexKey(in.getSessionHexKey());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return out;
	}

	/**
	 * Decodes a byte buffer with a AES session key.
	 * 
	 * @param in
	 *            CryptoInfo object with session key and data (encrypted) set.
	 * @return CryptoInfo object with session key and data (decrypted) set.
	 */
	public static CryptoInfo decodeAES(CryptoInfo in) {
		CryptoInfo out = null;
		try {
			ByteArrayInputStream bais = new ByteArrayInputStream(in.getData());
			byte[] iv = new byte[16];
			bais.read(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher symmetricCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			symmetricCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(hexToByte(in.getSessionHexKey()), "AES"), ivspec);
			CipherInputStream cis = new CipherInputStream(bais, symmetricCipher);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] bdata = new byte[1024];
			int read;
			while ((read = cis.read(bdata)) != -1) {
				baos.write(bdata, 0, read);
			}
			cis.close();
			baos.flush();
			baos.close();
			out = new CryptoInfo();
			out.setData(baos.toByteArray());
			out.setSessionHexKey(in.getSessionHexKey());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return out;
	}

	/**
	 * Encodes a byte buffer with a user-password.
	 * 
	 * @param in
	 *            CryptoInfo object with password and data (decrypted) set.
	 * @return CryptoInfo object with password and data (encrypted) set.
	 */
	public static CryptoInfo encodePasswordAES(CryptoInfo in) {
		CryptoInfo out = null;
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			KeySpec spec = new PBEKeySpec(in.getPassword().toCharArray(), new byte[] { 0 }, 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
			// Encrypt message
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(System.currentTimeMillis() * System.nanoTime());
			cipher.init(Cipher.ENCRYPT_MODE, secret, random);
			AlgorithmParameters params = cipher.getParameters();
			byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
			byte[] encrypted = cipher.doFinal(in.getData());
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			baos.write(iv.length);
			baos.write(iv);
			baos.write(encrypted);
			baos.flush();
			baos.close();
			// Store in return value
			out = new CryptoInfo();
			out.setData(baos.toByteArray());
			out.setPassword(in.getPassword());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return out;
	}

	/**
	 * Decodes a user-password encrypted byte buffer.
	 * 
	 * @param in
	 *            CryptoInfo object with password and data (encrypted) set.
	 * @return CryptoInfo object with password and data (decrypted) set.
	 */
	public static CryptoInfo decodePasswordAES(CryptoInfo in) {
		CryptoInfo out = null;
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			KeySpec spec = new PBEKeySpec(in.getPassword().toCharArray(), new byte[] { 0 }, 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
			// Decrypt message
			byte[] encrypted = in.getData();
			ByteArrayInputStream bais = new ByteArrayInputStream(encrypted);
			int ivlength = bais.read();
			byte[] iv = new byte[ivlength];
			bais.read(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
			CipherInputStream cis = new CipherInputStream(bais, cipher);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] bdata = new byte[1024];
			int read;
			while ((read = cis.read(bdata)) != -1) {
				baos.write(bdata, 0, read);
			}
			cis.close();
			baos.flush();
			baos.close();
			byte[] decrypted = baos.toByteArray();
			out = new CryptoInfo();
			out.setData(decrypted);
			out.setPassword(in.getPassword());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return out;
	}

	/**
	 * Class which holds all info required for the CryptoTool algorithms/methods.
	 * 
	 * @author Fabian David Tschopp
	 *
	 */
	public static class CryptoInfo {
		private byte[] data;
		private String publicHexKey;
		private String privateHexKey;
		private String sessionHexKey;
		private String password;

		public CryptoInfo() {

		}

		public byte[] getData() {
			return data;
		}

		public void setData(byte[] data) {
			this.data = data;
		}

		public String getPublicHexKey() {
			return publicHexKey;
		}

		public void setPublicHexKey(String publicHexKey) {
			this.publicHexKey = publicHexKey;
		}

		public String getPrivateHexKey() {
			return privateHexKey;
		}

		public void setPrivateHexKey(String privateHexKey) {
			this.privateHexKey = privateHexKey;
		}

		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}

		public String getSessionHexKey() {
			return sessionHexKey;
		}

		public void setSessionHexKey(String sessionHexKey) {
			this.sessionHexKey = sessionHexKey;
		}

	}

	/**
	 * UTF-8 password message disgest 5.
	 * 
	 * @param password
	 *            in plain text form.
	 * @return MD5 of password.
	 */
	public static String passwordMD5(String password) {
		try {
			byte[] bytes = password.getBytes("UTF-8");
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] digest = md.digest(bytes);
			return keyToHexString(digest);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Convert a hex-string to byte array.
	 * 
	 * @param s
	 * @return
	 */
	private static byte[] hexToByte(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * Convert a byte array to a hex-string.
	 * 
	 * @param keybytes
	 * @return
	 */
	private static String keyToHexString(byte[] keybytes) {
		StringBuffer retString = new StringBuffer();
		for (int i = 0; i < keybytes.length; ++i) {
			retString.append(Integer.toHexString(0x0100 + (keybytes[i] & 0x00FF)).substring(1));
		}
		return retString.toString();
	}

}
