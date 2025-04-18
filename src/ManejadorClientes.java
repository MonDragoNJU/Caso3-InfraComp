import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

public class ManejadorClientes extends Thread{
    private Socket socketCliente;
    private PrivateKey llavePrivada;
    private PublicKey llavePublica;
    private Map<Integer, String> servicios;

    public ManejadorClientes(Socket socketCliente, PrivateKey llavePrivada, PublicKey llavePublica, Map<Integer, String> servicios) {
        this.socketCliente = socketCliente;
        this.llavePrivada = llavePrivada;
        this.llavePublica = llavePublica;
        this.servicios = servicios;
    }

    @Override
    public void run() {
        try (
            ObjectOutputStream out = new ObjectOutputStream(socketCliente.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socketCliente.getInputStream())
        ) {
            //Recibir HELLO
            String hello = (String) in.readObject();
            if (!hello.equals("HELLO")) {
                System.out.println("ERROR AL RECIBIR HELLO");
                socketCliente.close();
                return;
            }

            //Recibir reto y cifrarlo
            byte[] reto = (byte[]) in.readObject();
            byte[] retoCifrado;
            try {
                retoCifrado = Utilidades.cifrarRSA(reto, llavePrivada);
            } catch (Exception e) {
                System.out.println("Error al cifrar el reto: " + e.getMessage());
                e.printStackTrace();
                socketCliente.close();
                return;
            }

            //Enviar reto cifrado al cliente
            out.writeObject(retoCifrado);
            out.flush();
            System.out.println("Reto cifrado enviado al cliente.");

            //Recibir respuesta del cliente
            String respuesta = (String) in.readObject();
            if (!respuesta.equals("OK")) {
                System.out.println("Cliente no autenticado.");
                socketCliente.close();
                return;
            }
            
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Error al manejar el cliente: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
