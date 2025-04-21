import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

public class Servidor extends Thread{
    private static final int PUERTO = 12345;
    private static PrivateKey llavePrivada;
    private static Map<Integer, String> servicios = new HashMap<>();
    private static Map<Integer, String> tablaIdsServicios = new HashMap<>();
    private int numeroClientes;

    Servidor(int numeroClientes) {
        this.numeroClientes = numeroClientes;
        
    }

    private void leerLlaves() throws IOException, ClassNotFoundException {
        FileInputStream archivoTexto1 = new FileInputStream("llaves/servidor_llave_privada.txt");
        ObjectInputStream oisTexto1 = new ObjectInputStream(archivoTexto1);
        llavePrivada = (PrivateKey) oisTexto1.readObject();
        oisTexto1.close();

    }

    private void llenarTablaServicios() {
        servicios.put(1, "Consulta Estado Vuelo;192.168.1.101;8080");
        servicios.put(2, "Disponibilidad Vuelos;192.168.1.102;8081");
        servicios.put(3, "Costo Vuelo;192.168.1.103;8082");

        tablaIdsServicios.put(1, "Consulta Estado Vuelo");
        tablaIdsServicios.put(2, "Disponibilidad Vuelos");
        tablaIdsServicios.put(3, "Costo Vuelo");
    }

    private void iniciarServidor() throws IOException {
        try (ServerSocket socketServidor = new ServerSocket(PUERTO)) {
            System.out.println("Servidor iniciado en el puerto " + PUERTO);
            for(int i = 0; i < numeroClientes; i++) {
                Socket socket = socketServidor.accept();
                System.out.println("Cliente conectado: " + socket.getInetAddress().getHostAddress());
                new ManejadorClientes(socket, llavePrivada, servicios, tablaIdsServicios).start();
            }
        }
    }

    @Override
    public void run() {
        try {
            leerLlaves();
            llenarTablaServicios();
            iniciarServidor();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error al ejecutar el servidor: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
}

