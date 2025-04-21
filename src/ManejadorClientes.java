import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

public class ManejadorClientes extends Thread {
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
            if (!recibirHello(in)) return;

            byte[] reto = (byte[]) in.readObject();
            byte[] retoCifrado = cifrarRetoRSA(reto);
            if (retoCifrado == null) return;

            enviarObjeto(out, retoCifrado, "Reto cifrado enviado al cliente.");

            if (!validarRespuestaCliente(in)) return;

            DHParameterSpec dhSpec = generarParametrosDH();
            if (dhSpec == null) return;

            BigInteger g = dhSpec.getG();
            BigInteger p = dhSpec.getP();
            BigInteger x = new BigInteger(1024 - 1, new SecureRandom());
            BigInteger gX = g.modPow(x, p);

            long inicioFirma = System.nanoTime();
            byte[] firma = firmarParametros(g, p, gX);
            long finFirma = System.nanoTime();
            double tiempoMs = (finFirma - inicioFirma) / 1_000_000.0;
            MedidorTiempos.escribirTiempo("Firma", "Firma", tiempoMs);

            out.writeObject(g);
            out.writeObject(p);
            out.writeObject(gX);
            out.writeObject(firma);
            out.flush();
            System.out.println("SERVIDOR - G, P, G^X y firma enviados al cliente.");

            if (!validarRespuestaCliente(in)) return;

            BigInteger gY = (BigInteger) in.readObject();
            BigInteger gXy = gY.modPow(x, p);
            byte[] secreto = Utilidades.intToBytes(gXy.intValue());

            SecretKey llaveAES = Utilidades.derivarLlaves(secreto)[0];
            SecretKey llaveHMAC = Utilidades.derivarLlaves(secreto)[1];

            byte[] iv = (byte[]) in.readObject();

            long inicioCifrado = System.nanoTime();
            byte[] idsServiciosCifrados = Utilidades.cifrarAES(Utilidades.serializar(tablaIdsServicios), llaveAES, iv);
            enviarObjeto(out, idsServiciosCifrados, "Tabla de ids de servicios cifrados enviada al cliente.");
            long finCifrado = System.nanoTime();
            tiempoMs = (finCifrado - inicioCifrado) / 1_000_000.0;
            MedidorTiempos.escribirTiempo("CifradoTabla", "Cifrado", tiempoMs);

            enviarHMAC(out, idsServiciosCifrados, llaveHMAC, "HMAC de la tabla de ids de servicios enviada al cliente.");

            byte[] eleccionIdCifrado = (byte[]) in.readObject();
            byte[] hmacEleccion = (byte[]) in.readObject();

            if (!verificarHMAC(eleccionIdCifrado, hmacEleccion, llaveHMAC)) return;

            byte[] eleccionIdCifradoDesencriptado = Utilidades.descifrarAES(eleccionIdCifrado, llaveAES, iv);
            String eleccionId = new String(eleccionIdCifradoDesencriptado, "UTF-8");

            String[] partes = eleccionId.split(";");
            int idServicio = Integer.parseInt(partes[0]);

            String infoServidor = servicios.get(idServicio);
            byte[] infoServidorCifrado = Utilidades.cifrarAES(infoServidor.getBytes(), llaveAES, iv);
            enviarObjeto(out, infoServidorCifrado, "IP y puerto del servicio enviado al cliente.");

            enviarHMAC(out, infoServidorCifrado, llaveHMAC, "HMAC de la ip y puerto del servicio enviado al cliente.");

            if (!validarRespuestaCliente(in)) return;

            System.out.println("SERVIDOR - Conexión con el cliente finalizada. Redirigiendo al cliente al servicio.");
            socketCliente.close();

        } catch (Exception e) {
            System.out.println("Error en la consulta: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private boolean recibirHello(ObjectInputStream in) throws Exception {
        String hello = (String) in.readObject();
        if (!hello.equals("HELLO")) {
            System.out.println("SERVIDOR - Error al recibir HELLO");
            socketCliente.close();
            return false;
        }
        return true;
    }

    private byte[] cifrarRetoRSA(byte[] reto) {
        try {
            return Utilidades.cifrarRSA(reto, llavePrivada);
        } catch (Exception e) {
            System.out.println("SERVIDOR - Error al cifrar el reto: " + e.getMessage());
            e.printStackTrace();
            cerrarConexion();
            return null;
        }
    }

    private boolean validarRespuestaCliente(ObjectInputStream in) throws Exception {
        String respuesta = (String) in.readObject();
        if (!respuesta.equals("OK")) {
            System.out.println("SERVIDOR - Cliente no autenticado.");
            socketCliente.close();
            return false;
        }
        return true;
    }

    private DHParameterSpec generarParametrosDH() {
        try {
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            AlgorithmParameters params = paramGen.generateParameters();
            return params.getParameterSpec(DHParameterSpec.class);
        } catch (Exception e) {
            System.out.println("SERVIDOR - Error al generar parámetros DH: " + e.getMessage());
            e.printStackTrace();
            cerrarConexion();
            return null;
        }
    }

    private byte[] firmarParametros(BigInteger g, BigInteger p, BigInteger gX) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(llavePrivada);
        sig.update(g.toByteArray());
        sig.update(p.toByteArray());
        sig.update(gX.toByteArray());
        return sig.sign();
    }

    private void enviarObjeto(ObjectOutputStream out, Object objeto, String mensaje) throws Exception {
        out.writeObject(objeto);
        out.flush();
        System.out.println("SERVIDOR - " + mensaje);
    }

    private void enviarHMAC(ObjectOutputStream out, byte[] datos, SecretKey llaveHMAC, String mensaje) throws Exception {
        byte[] hmac = Utilidades.hmac(datos, llaveHMAC);
        out.writeObject(hmac);
        out.flush();
        System.out.println("SERVIDOR - " + mensaje);
    }

    private boolean verificarHMAC(byte[] datos, byte[] hmacRecibido, SecretKey llaveHMAC) throws Exception {
        byte[] hmacCalculado = Utilidades.hmac(datos, llaveHMAC);
        if (!Arrays.equals(hmacRecibido, hmacCalculado)) {
            System.out.println("Error de autenticación: HMAC no coincide.");
            cerrarConexion();
            return false;
        }
        return true;
    }

    private void cerrarConexion() {
        try {
            socketCliente.close();
        } catch (Exception e) {
        }
    }
}
