import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;

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

    public static byte[] intToBytes(int numero) {
        return new byte[] {
            (byte)(numero >> 24),
            (byte)(numero >> 16),
            (byte)(numero >> 8),
            (byte)(numero)
        };
    }

    // Convertir byte[] a int
    public static int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
               ((bytes[1] & 0xFF) << 16) |
               ((bytes[2] & 0xFF) << 8) |
               (bytes[3] & 0xFF);
    }

    public static SecretKey[] derivarLlaves(byte[] secreto) throws NoSuchAlgorithmException {
        //Calcular digest SHA-512 del secreto
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hash = digest.digest(secreto); 

        //Particionar el hash
        byte[] primeros256bits = Arrays.copyOfRange(hash, 0, 32); // Bytes 0-31
        byte[] ultimos256bits = Arrays.copyOfRange(hash, 32, 64); // Bytes 32-63

        //Construir llaves
        SecretKey llaveAES = new SecretKeySpec(primeros256bits, "AES");
        SecretKey llaveHMAC = new SecretKeySpec(ultimos256bits, "HmacSHA256");

        return new SecretKey[]{llaveAES, llaveHMAC};
    }

    public static byte[] cifrarAES(byte[] mensaje, SecretKey llaveAES, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, llaveAES, new IvParameterSpec(iv));
        byte[] mensajeCifrado = cipher.doFinal(mensaje);
        return mensajeCifrado;
    }

    public static byte[] hmac(byte[] mensaje, SecretKey llaveHMAC) throws NoSuchAlgorithmException {
        Mac mac = Mac.getInstance("HmacSHA256");
        try {
            mac.init(llaveHMAC);
            return mac.doFinal(mensaje);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Error al inicializar HMAC", e);
        }
    }

    public static byte[] descifrarAES(byte[] mensajeCifrado, SecretKey llaveAES, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, llaveAES, new IvParameterSpec(iv));
        return cipher.doFinal(mensajeCifrado);
    }

    public static byte[] serializar(Object objeto) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(objeto);
        return baos.toByteArray();
    }

    public static Object deserializar(byte[] datos) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bais = new ByteArrayInputStream(datos);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }
    
}
