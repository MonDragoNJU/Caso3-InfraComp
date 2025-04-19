import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Map;
import java.util.Set;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

public class ManejadorClientes extends Thread{
    private Socket socketCliente;
    private PrivateKey llavePrivada;
    private Map<Integer, String> servicios;
    private Map<Integer, String> tablaIdsServicios;

    public ManejadorClientes(Socket socketCliente, PrivateKey llavePrivada, Map<Integer, String> servicios, Map<Integer, String> tablaIdsServicios) {
        this.socketCliente = socketCliente;
        this.llavePrivada = llavePrivada;
        this.servicios = servicios;
        this.tablaIdsServicios = tablaIdsServicios;
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

            //Generar G, P, G^X
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec;
            try {
                dhSpec = params.getParameterSpec(DHParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                System.out.println("Error al obtener parámetros de Diffie-Hellman: " + e.getMessage());
                e.printStackTrace();
                socketCliente.close();
                return;
            }

            BigInteger g = dhSpec.getG();
            BigInteger p = dhSpec.getP();

            SecureRandom random = new SecureRandom();
            BigInteger x = new BigInteger(1024 - 1, random);

            BigInteger gX = g.modPow(x, p);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(llavePrivada);
            sig.update(g.toByteArray());
            sig.update(p.toByteArray());
            sig.update(gX.toByteArray());
            byte[] firma = sig.sign();

            //Enviar G, P, G^X y firma al cliente
            out.writeObject(g);
            out.writeObject(p);
            out.writeObject(gX);
            out.writeObject(firma);
            out.flush();

            System.out.println("G, P, G^X y firma enviados al cliente.");

            //Recibir respuesta del cliente
            String respuestaCliente = (String) in.readObject();
            if (!respuestaCliente.equals("OK")) {
                System.out.println("Cliente no autenticado.");
                socketCliente.close();
                return;
            }

            //Recibir G^Y del cliente
            BigInteger gY = (BigInteger) in.readObject();

            //Calcular (G^y)^x mod p
            BigInteger gXy = gY.modPow(x, p);
            byte[] secreto = Utilidades.intToBytes(gXy.intValue());

            //Generar llave simetrica para cifrar K_AB1
            
            SecretKey llaveAES = Utilidades.derivarLlaves(secreto)[0];

            //Generar llave simetrica para MAC K_AB2

            SecretKey llaveHMAC = Utilidades.derivarLlaves(secreto)[1];

            //Recibir vector de inicializacion del cliente
            byte[] iv = (byte[]) in.readObject();

            //Mandar tabla de ids de servicios al cliente cifrados

            

            
        } catch (Exception e) {
            System.out.println("Error en la consulta: " + e.getMessage());
            e.printStackTrace();
        }
    }

}
