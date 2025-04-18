import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
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

            // Enviar respuesta al servidor
            out.writeObject("OK");
            out.flush();

            System.out.println("SIUUU");

        } catch (IOException | ClassNotFoundException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error al iniciar el cliente: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        new Cliente().iniciarCliente();
    }
}
