package firewall;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import crypto.B64;
import dbg.Dbg;
import dbg.Dbg.Color;

public class Firewall implements Runnable {
  DatagramSocket firewallSocket = null;
  InetAddress host;
  int port;
  Boolean active = true;
  byte[] receiveBuffer;
  byte[] sendBuffer;
  String message;
  String response;
  DatagramPacket receiveDatagram;
  DatagramPacket sendPacket;
  List<Protocol> permittedProtocols;

  public Firewall(int port) {

    permittedProtocols = new ArrayList<>();

    permittedProtocols.add(new Protocol("*", "5050", "start"));
    permittedProtocols.add(new Protocol("*", "5050", "login"));
    permittedProtocols.add(new Protocol("*", "5050", "signup"));
    permittedProtocols.add(new Protocol("*", "5050", "withdraw"));
    permittedProtocols.add(new Protocol("*", "5050", "deposit"));
    permittedProtocols.add(new Protocol("*", "5050", "balance"));
    permittedProtocols.add(new Protocol("*", "5050", "transfer"));
    permittedProtocols.add(new Protocol("*", "5050", "investment"));

    permittedProtocols.add(new Protocol("5050", "*", "*"));

    this.port = port;
    Thread t = new Thread(this);
    t.start();

    try {
      t.join();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }

  public void run() {
    try {

      firewallSocket = new DatagramSocket(port);
      host = InetAddress.getByName("localhost");
      Dbg.log();
      Dbg.log(Color.PURPLE, "Firewall online em: " +
          host +
          ":" +
          port);

      while (active) {
        var res = receiveMessage();

        var head = res.split("/body")[0];

        var protocol = new Protocol(head.split(":")[0], head.split(":")[1], head.split(":")[2]);

        // if (isPermitted(protocol)) {
        if (true) {
          Dbg.log(Color.GREEN,
              "Protocolo permitido: " + protocol.origin + " -> " + protocol.destination + " : " + protocol.action);
          sendMessage(B64.encode(res), Integer.valueOf(head.split(":")[1]));
        } else {
          Dbg.log(Color.RED, "Protocolo não permitido: " + protocol.origin + " -> " + protocol.destination + " : "
              + protocol.action);
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public Boolean isPermitted(Protocol protocol) {
    return permittedProtocols.stream().filter(p -> p.origin == "*" || p.origin.equals(protocol.origin))
        .filter(p -> p.destination == "*" || p.destination.equals(protocol.destination))
        .filter(p -> p.action == "*" || p.action.equals(protocol.action))
        .findFirst().isPresent();
  }

  public void sendMessage(String message, int port) {
    try {
      sendBuffer = message.getBytes();
      sendPacket = new DatagramPacket(sendBuffer, sendBuffer.length, host, port);
      firewallSocket.send(sendPacket);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public String receiveMessage() {
    try {
      receiveBuffer = new byte[10240];
      receiveDatagram = new DatagramPacket(receiveBuffer, receiveBuffer.length);
      firewallSocket.receive(receiveDatagram);
      return B64.decode(new String(receiveDatagram.getData()));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
}
