package p2;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Demostración de cifrado AES con Bouncy Castle
 *
 */
public class AES {
	// Creamos un "motor" AES con un tamaño de bloque de 16 bytes
	public final int blockSize = 16;
	public final int keySize = 24;

	/**
	 * Gestiona la creación de una clave AES y la almacena en un archivo en
	 * formato Hexadecimal para que sea legible al abrirlo
	 */
	public void doGenerateKey() {
		byte[] key = generateKeyAndIV();
		if (key != null) {
			System.out.println("Key generated:"
					+ new String(Hex.encode(Arrays.copyOfRange(key, 0, keySize))));
			System.out.println("IV generated:"
					+ new String(Hex.encode(Arrays.copyOfRange(key, keySize,
							blockSize + keySize))));
			Utils.instance().saveFile("aeskeyiv", Hex.encode(key));
		}
	}

	/**
	 * Gestiona el cifrado de un archivo txt (leyendo tambien el archivo de la
	 * clave AES)
	 */
	public void doEncrypt() {
		byte[] text = Utils.instance().doSelectFile(
				"Select a file to encrypt", "txt");
		if (text != null) {
			byte[] key = Utils.instance().doSelectFile("Select a key",
					"aeskeyiv");
			if (key != null) {
				byte[] res = encrypt(text,
						Arrays.copyOfRange(Hex.decode(key), 0, keySize),
						Arrays.copyOfRange(Hex.decode(key), keySize, keySize + blockSize));
				System.out.println("Texto cifrado (en hexadecimal):"
						+ new String(Hex.encode(res)));
				Utils.instance().saveFile("encaes", Hex.encode(res));
			}
		} else {
			// No se desea continuar con la ejecución
		}

	}

	/**
	 * Gestiona el descifrado de un archivo (leyendo tambien el archivo de la
	 * clave AES)
	 */
	public void doDecrypt() {
		byte[] fileContent = Utils.instance().doSelectFile(
				"Select an encrypted file to decrypt", "encaes");
		if (fileContent == null) {
			return;
		}
		byte[] key = Utils.instance().doSelectFile("Select a key",
				"aeskeyiv");
		if (key != null) {
			byte[] res = decrypt(Hex.decode(fileContent),
					Arrays.copyOfRange(Hex.decode(key), 0, keySize),
					Arrays.copyOfRange(Hex.decode(key), keySize, blockSize + keySize));
			if (res != null) {
				System.out.println("Cleartext:" + new String(res));
			}
		}

	}

	/**
	 * Cifra/Descifra datos con el algoritmo AES. Al ser un algoritmo de cifrado
	 * simétrico se puede usar para ambos procesos
	 * 
	 * @param cipher
	 *            Cifrador/Descifrador AES
	 * @param data
	 *            Datos origen
	 * @return Datos destino
	 * @throws Exception
	 */
	private static byte[] cipherData(PaddedBufferedBlockCipher cipher,
			byte[] data) throws Exception {
		// Creamos un array de bytes del tamaño estimado de descifrado
		int minSize = cipher.getOutputSize(data.length);
		byte[] outBuf = new byte[minSize];
		// Procesamos todos los bytes de los datos
		int length1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
		// Realizamos el procesamiento final (conceptualmente, es como el flush de los streams)
		int length2 = cipher.doFinal(outBuf, length1);
		int actualLength = length1 + length2;
		byte[] result = new byte[actualLength];
		// Copiamos el resultado y lo devolvemos
		System.arraycopy(outBuf, 0, result, 0, result.length);
		return result;
	}

	/**
	 * Descifra datos usando el algoritmo AES
	 * Tanto el método de cifrado como el de descifrado se pueden realizar como uno sólo, 
	 * pero se mantienen separados por claridad del código para el alumno
	 * 
	 * @param ciphered
	 *            Datos cifrados
	 * @param key
	 *            Clave (keySize bytes)
	 * @param iv
	 *            Vector de Inicialización (Tamaño en bytes del bloque)
	 * @return Datos descifrados
	 */
	private static byte[] decrypt(byte[] ciphered, byte[] key, byte[] iv) {
		try {
			// Creamos el cifrador
			PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(
					new CBCBlockCipher(new AESEngine()));
			// Procesamos la clave y el IV
			CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(
					key), iv);
			aes.init(false, ivAndKey);
			return cipherData(aes, ciphered);
		} catch (Exception e) {
			System.out
					.println("There was an error while decrypting the text:"
							+ e);
			return null;
		}
	}

	/**
	 * Cifra datos usando el algoritmo AES
	 * 
	 * @param datos
	 *            a cifrar
	 * @param key
	 *            Clave (keySize bytes)
	 * @param iv
	 *            Vector de Inicialización (Tamaño en bytes del bloque)
	 * @return Datos cifrados
	 */
	private static byte[] encrypt(byte[] plain, byte[] key, byte[] iv) {
		try {
			PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(
					new CBCBlockCipher(new AESEngine()));
			CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(
					key), iv);
			aes.init(true, ivAndKey);
			return cipherData(aes, plain);
		} catch (Exception e) {
			System.out
					.println("There was an error while encrypting the text:"
							+ e);
			return null;
		}
	}

	/**
	 * Genera una Clave e IV para el cifrado AES a partir de un número aleatorio
	 * "seguro"
	 * 
	 * @return keySize+blocksize bytes (Clave+IV)
	 */
	public byte[] generateKeyAndIV() {
		// Usamos el generador de números aleatorios para criptografía
		SecureRandom sr = null;
		try {
			sr = new SecureRandom();
			// Lo inicializamos con una semilla
			sr.setSeed("UCTresM.".getBytes());
		} catch (Exception e) {
			System.err
					.println("There was an error while generating the random number");
			return null;
		}
		// Lo generamos del tamaño que necesitamos (24 bytes de clave + tamaño de bloque como IV)
		byte[] key = sr.generateSeed(keySize + blockSize);
		return key;

	}
}
