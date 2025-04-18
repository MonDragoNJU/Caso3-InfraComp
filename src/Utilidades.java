import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class Utilidades {
    public static byte[] cifrarRSA(byte[] mensaje, PrivateKey llavePrivada) throws IllegalBlockSizeException, BadPaddingException, Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, llavePrivada);
        return cipher.doFinal(mensaje);
    }

    public static byte[] descifrarRSA(byte[] mensaje, PublicKey llavePublica) throws IllegalBlockSizeException, BadPaddingException, Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, llavePublica);
        return cipher.doFinal(mensaje);
    }

    public static byte[] generarReto(int longitud) {
        byte[] reto = new byte[longitud];
        SecureRandom random = new SecureRandom();
        random.nextBytes(reto);
        return reto;
    }
}
