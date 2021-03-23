package p2;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * Demostración de cifrado DES con Bouncy Castle
*/
public class DES {
	BlockCipher engine = new DESEngine();

	/**
	 * Gestiona la creación de una clave DES
	 */
	public void doGenerateKey() {
		byte[] key = generateKey();
		if (key != null) {
			System.out.println("Key generated:" + new String(Hex.encode(key)));
			Utils.instance().saveFile("deskey", Hex.encode(key));
		}
	}

	/**
	 * Gestiona el cifrado de un archivo usando el algoritmo DES y una clave alamcenada también en otro archivo
	 */
	public void doEncrypt() {
		// Archivo a cifrar
		byte[] text = Utils.instance().doSelectFile("Select a file to encrypt", "txt");
		if (text!=null) {
			// Clave a usar
			byte[] key = Utils.instance().doSelectFile("Select a key",
					"deskey");
			if (key != null) {
				// La almacenamos en hexadecimal para que sea legible en el archivo
				byte[] res = encrypt(Hex.decode(key),text);
				System.out.println("Ciphertext (hexadecimal):"
						+ new String(Hex.encode(res)));
				Utils.instance().saveFile("encdes", Hex.encode(res));
			}
		} else {
			// No se desea continuar con la ejecución
		}

	}
	/**
	 * Gestiona el descifrado de un archivo usando el algoritmo DES y una clave almacenada también en otro archivo
	 */
	public void doDecrypt() {
		// Archivo a descifrar
		byte[] fileContent = Utils.instance().doSelectFile(
				"Select an encrypted file to decrypt", "encdes");
		if (fileContent == null) {
			return;
		}
		// Clave a usar
		byte[] key = Utils.instance().doSelectFile("Select a key",
				"deskey");
		if (key != null) {
			// Desciframos el archivo
			byte[] res = decrypt(Hex.decode(key), Hex.decode(fileContent));
			if (res != null) {
				System.out.println("Cleartext:"
						+ new String(res));
			}
		}

	}

	/**
	 * Realiza el cifrado DES de los datos
	 * @param key Clave
	 * @param ptBytes Texto a cifrar
	 * @return Texto cifrado
	 */
	protected byte[] encrypt(byte[] key, byte[] ptBytes) {
		// Creamos un cifrador de Bloque con Padding y con el modo de bloque CBC
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				new CBCBlockCipher(engine));
		// Lo inicializamos con la clave
		cipher.init(true, new KeyParameter(key));
		// Reservamos espacio para el texto cifrado
		byte[] rv = new byte[cipher.getOutputSize(ptBytes.length)];
		// Realizamos el procesamiento con DES
		int tam = cipher.processBytes(ptBytes, 0, ptBytes.length, rv, 0);
		try {
			// "flush" del cifrador
			cipher.doFinal(rv, tam);
		} catch (Exception ce) {
			ce.printStackTrace();
			return null;
		}
		// Devolvemos los datos cifrados
		return rv;
	}

	/**
	 * Realiza el descifrado DES de los datos
	 * Este método podría obviarse y utilizarse el método encrypt para realizar el descifrado al ser
	 * el algoritmo DES un algoritmo simétrico, pero se mantiene por criterios de claridad para el alumno
	 * @param key Clave
	 * @param ptBytes Texto a descifrar
	 * @return Texto descifrado
	 */
	public byte[] decrypt(byte[] key, byte[] cipherText) {
		// Creamos un cifrador de Bloque con Padding y con el modo de bloque CBC
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				new CBCBlockCipher(engine));
		// Lo inicializamos con la clave
		cipher.init(false, new KeyParameter(key));
		// Reservamos espacio para el texto descifrado
		byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];
		// Realizamos el procesamiento con DES
		int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
		try {
			// "flush" del cifrador
			cipher.doFinal(rv, tam);
		} catch (Exception ce) {
			System.out.println("There was an error while decrypting the message:"+ce.getLocalizedMessage());
			//			ce.printStackTrace();
			return null;
		}
		// Devolvemos los datos descifrados
		return rv;
	}

	/**
	 * Genera una Clave para el cifrado DES a partir de un número aleatorio
	 * "seguro"
	 * 
	 * @return Clave generada con la longitud de DESParameters
	 */
	public byte[] generateKey() {
		// Creamos un generador de aleatorios "seguro"
		SecureRandom sr = null;
		try {
			sr = new SecureRandom();
			sr.setSeed("UCTresM.".getBytes());
		} catch (Exception e) {
			System.err
					.println("There was an error while generating the random number");
			return null;
		}
		
		// Generamos la clave DES con la longitud necesaria para el algoritmo
		KeyGenerationParameters kgp = new KeyGenerationParameters(sr,
				(DESParameters.DES_KEY_LENGTH) * 8);

		DESKeyGenerator kg = new DESKeyGenerator();
		kg.init(kgp);

		/*
		 * Third, and finally, generate the key
		 */
		byte[] key = kg.generateKey();
		return key;

	}
}
