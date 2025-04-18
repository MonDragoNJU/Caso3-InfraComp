import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class GeneradorLlaves {

    private static final String ALGORITMO = "RSA";

    private void almacenarLlave(Key llave, String archivoS) throws NoSuchAlgorithmException, IOException {
        FileOutputStream archivo = new FileOutputStream(archivoS);
        ObjectOutputStream oos = new ObjectOutputStream(archivo);
        oos.writeObject(llave);
        oos.close();
    }

    public void generarLlaves() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITMO);
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        Key llavePrivada = keyPair.getPrivate();
        Key llavePublica = keyPair.getPublic();

        almacenarLlave(llavePublica, "llaves/servidor_llave_publica.txt");
        almacenarLlave(llavePrivada, "llaves/servidor_llave_privada.txt");

        System.out.println("Llaves generadas correctamente siu");
    }
}
