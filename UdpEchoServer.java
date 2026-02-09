import java.net.*;
import java.nio.charset.StandardCharsets;

public class UdpEchoServer {
  public static void main(String[] args) throws Exception {
    int port = args.length > 0 ? Integer.parseInt(args[0]) : 5556;

    try (DatagramSocket sock = new DatagramSocket(port)) {
      System.out.println("UDP EchoServer on port " + port);

      byte[] buf = new byte[2048];
      DatagramPacket pkt = new DatagramPacket(buf, buf.length);

      while (true) {
        sock.receive(pkt);
        String msg = new String(pkt.getData(), pkt.getOffset(), pkt.getLength(), StandardCharsets.UTF_8);

        String reply = "echo: " + msg;
        byte[] out = reply.getBytes(StandardCharsets.UTF_8);

        DatagramPacket resp = new DatagramPacket(out, out.length, pkt.getAddress(), pkt.getPort());
        sock.send(resp);

        pkt.setLength(buf.length); // reset pra próxima recepção
      }
    }
  }
}
