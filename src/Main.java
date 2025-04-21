import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        GeneradorLlaves generador = new GeneradorLlaves();
        try {
            generador.generarLlaves();
            System.out.println("Llaves generadas correctamente.");
        } catch (Exception e) {
            System.out.println("Error al generar las llaves: " + e.getMessage());
        }

        System.out.println("Bienvenido al sistema de gestión de vuelos.");
        System.out.println("Vamos a probar los escenarios de cliente y servidor.");
        System.out.println("1. Escenario de cliente y servidor con un solo cliente iterativo.");
        System.out.println("2. Escenario de cliente y servidor con múltiples clientes concurrentes.");
        System.out.println("Elija una opción (1 o 2): ");
        Scanner scanner = new Scanner(System.in);
        int opcion = scanner.nextInt();
        switch (opcion) {
            case 1:
                Servidor servidor = new Servidor(32);
                servidor.start();
                System.out.println("Servidor ejecutándose en modo iterativo.");
                System.out.println("Iniciando cliente...");
                Cliente cliente = new Cliente();
                for (int i = 0; i < 32; i++) {
                    cliente.iniciarCliente();
                }
                break;
            case 2:
            
                System.out.println("Seleccione el numero de delegados concurrentes (4, 16, 32, 64): ");
                int numDelegados = scanner.nextInt();
                Servidor servidor2 = new Servidor(numDelegados);
                servidor2.start();
                System.out.println("Servidor ejecutándose en modo concurrente.");
                System.out.println("Iniciando cliente...");
                Cliente[] clientes = new Cliente[numDelegados];
                for (int i = 0; i < numDelegados; i++) {
                    cliente = new Cliente();
                    clientes[i] = cliente;
                    clientes[i].start();
                    System.out.println("Cliente " + (i + 1) + " iniciado.");
                }
                for (int i = 0; i < numDelegados; i++) {
                    try {
                        clientes[i].join();
                    } catch (InterruptedException e) {
                        System.out.println("Error al esperar al cliente " + (i + 1) + ": " + e.getMessage());
                    }
                }
                break;
        
            default:
                break;
            
        }

        scanner.close();
        System.out.println("Fin del programa.");

    }
}
