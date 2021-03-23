package p2;

import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Ejecuta distintas funciones resumen
 */
public class Hash {
	
	/**
	 * Establece la función resumen MD5 para el procesamiento
	 */
	public void doMD5() {
		doDigest(new MD5Digest());
	}

	/**
	 * Establece la función resumen SHA1 para el procesamiento
	 */
	public void doSHA1() {
		doDigest(new SHA1Digest());
	}

	/**
	 * Gestiona un digest de un archivo
	 * @param digest
	 * @return
	 */
	protected byte[] doDigest(GeneralDigest digest) {
		byte[] fileContent = Utils.instance().doSelectFile(
				"Select a file", "txt");
		if (fileContent != null) {
			byte[] result = digest(digest, fileContent);
			System.out.println("The hash is:" + new String(Hex.encode(result)));
			return result;
		}
		return null;
	}

	/**
	 * Realiza el procesamiento de la función resumen seleccionada
	 * @param digest
	 * @param input
	 * @return
	 */
	public byte[] digest(GeneralDigest digest, byte[] input) {
		digest.update(input, 0, input.length);

		// get the output/ digest size and hash it
		byte[] result = new byte[digest.getDigestSize()];
		digest.doFinal(result, 0);
		return result;
	}

}
