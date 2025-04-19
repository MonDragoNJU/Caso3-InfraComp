import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.SecretKey;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;

public class Cliente {

    static String host = "localhost";
    static int puerto = 12345;
    static PublicKey llavePublica;

    public Cliente() {
        leerLlave();
    }

    private void leerLlave() {
        try (FileInputStream archivoTexto = new FileInputStream("llaves/servidor_llave_publica.txt");
             ObjectInputStream oisTexto = new ObjectInputStream(archivoTexto)) {
            llavePublica = (PublicKey) oisTexto.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Error al leer la llave pública: " + e.getMessage());
        }
    }

    private void iniciarCliente() throws Exception {
        try (Socket socketCliente = new Socket(host, puerto)) {
            System.out.println("Conectado al servidor en " + host + ":" + puerto);
            ObjectOutputStream out = new ObjectOutputStream(socketCliente.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socketCliente.getInputStream());

            // Enviar HELLO al servidor
            out.writeObject("HELLO");
            System.out.println("HELLO enviado al servidor.");
            out.flush();

            //Crear reto y enviarlo al servidor
            byte[] reto = Utilidades.generarReto(16); 
            out.writeObject(reto);
            out.flush();

            // Recibir reto del servidor
            byte[] retoCifrado = (byte[]) in.readObject();
            byte[] retoDescifrado = Utilidades.descifrarRSA(retoCifrado, llavePublica);

            if (!java.util.Arrays.equals(reto, retoDescifrado)) {
                System.out.println("Error de autenticación: el reto no coincide.");
                out.writeObject("ERROR");
                out.flush();
            }

            System.out.println("Reto validado");

            // Enviar respuesta al servidor
            out.writeObject("OK");
            out.flush();

            //Recibir G, P, G^X, F(K_w-, (G, P, G^x)) del servidor
            BigInteger g = (BigInteger) in.readObject();
            BigInteger p = (BigInteger) in.readObject();
            BigInteger gX = (BigInteger) in.readObject();
            byte[] firma = (byte[]) in.readObject();

            //Verificar firma del servidor
            Signature sigVerif = Signature.getInstance("SHA256withRSA");
            sigVerif.initVerify(llavePublica);
            sigVerif.update(g.toByteArray());
            sigVerif.update(p.toByteArray());
            sigVerif.update(gX.toByteArray());
            boolean esValida = sigVerif.verify(firma);

            if (esValida) {
                System.out.println("Firma válida. Autenticación exitosa.");
                out.writeObject("OK");
                out.flush();
            } else {
                System.out.println("Firma inválida. Autenticación fallida.");
                out.writeObject("ERROR");
                out.flush();
                return;
            }

            //Generar G^y
            SecureRandom random = new SecureRandom();
            BigInteger y = new BigInteger(1024 - 1, random);

            BigInteger gY = g.modPow(y, p);

            //Calcular (G^x)^y mod p
            BigInteger gXy = gX.modPow(y, p);
            byte[] secreto = Utilidades.intToBytes(gXy.intValue());

            //Generar llave simetrica para cifrar K_AB1
            
            SecretKey llaveAES = Utilidades.derivarLlaves(secreto)[0];

            //Generar llave simetrica para MAC K_AB2

            SecretKey llaveHMAC = Utilidades.derivarLlaves(secreto)[1];

            //Enviar G^y al servidor
            out.writeObject(gY);
            out.flush();

            //Enviar vector de inicializacion al servidor
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            out.writeObject(iv);
            out.flush();



            







        } catch (Exception e) {
            System.out.println("Error al iniciar el cliente: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        new Cliente().iniciarCliente();
    }
}
