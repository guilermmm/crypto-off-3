package firewall;

public class Protocol {
  String origin, destination, action;

  public Protocol(String origin, String destination, String action) {
    this.origin = origin;
    this.destination = destination;
    this.action = action;
  }

  public String toString() {
    return origin + ":" + destination + ":" + action;
  }
}
