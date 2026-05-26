import requests
import argparse
import sys

DEFAULT_CLIENT = "http://127.0.0.1:8082"


def ask(prompt, default=None, cast=str):
    suffix = f" [{default}]" if default is not None else ""
    while True:
        raw = input(f"  {prompt}{suffix}: ").strip()
        if not raw and default is not None:
            return default
        if not raw:
            continue
        try:
            return cast(raw)
        except ValueError:
            print("  ✗ Valor inválido.")


def send(client_url, dst_ip, dst_port, protocol, message):
    print(f"\n  Enviando → {dst_ip}:{dst_port}/{protocol}  msg='{message}'")
    print("  " + "─" * 42)
    try:
        r = requests.post(
            f"{client_url}/send",
            json={
                "dst_ip":   dst_ip,
                "dst_port": int(dst_port),
                "protocol": protocol.upper(),
                "message":  message
            },
            timeout=8
        )
        data = r.json()

        if r.status_code == 403 or data.get("status") == "BLOCK":
            print(f"  ✗ BLOQUEADO por firewall SDN")
            print(f"    Razón : {data.get('reason', 'regla activa')}")
        elif r.status_code == 502:
            print(f"  ✗ ERROR: nodo destino no responde")
            print(f"    {data.get('reason', '')}")
        elif data.get("status") == "PERMIT":
            print(f"  ✓ ENTREGADO")
            print(f"  ← Respuesta de {data.get('from', dst_ip)}: {data.get('reply', '')}")
        else:
            print(f"  ? {data}")

    except requests.ConnectionError:
        print(f"  ✗ No se pudo conectar al cliente local en {client_url}")
        print(f"    ¿Está corriendo client.py?")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    print()


def interactive(client_url):
    # Mostrar nodos registrados para ayudar al usuario
    try:
        r = requests.get(f"{client_url.rsplit(':',1)[0].replace(str(client_url.split(':')[-1]),'')}".rstrip(':') + "/clients" if False else
                         f"{client_url}", timeout=2)
    except:
        pass

    print("\n  SDN Firewall — Generador de tráfico")
    print("  " + "─" * 42)
    print(f"  Cliente local : {client_url}")
    print("  " + "─" * 42)

    dst_ip   = ask("IP destino")
    dst_port = ask("Puerto destino", cast=int)
    protocol = ask("Protocolo (TCP/UDP)", default="TCP").upper()
    message  = ask("Mensaje", default="test")

    send(client_url, dst_ip, dst_port, protocol, message)


def parse_args():
    p = argparse.ArgumentParser(
        description="Generador de tráfico SDN",
        epilog="""
Ejemplos:
  python trafic.py --dst-ip 192.168.0.12 --dst-port 8082 --proto TCP --msg "hola"
  python trafic.py --dst-ip 192.168.0.13 --dst-port 9001 --proto UDP --msg "ping"
        """
    )
    p.add_argument("--client",   default=DEFAULT_CLIENT, help="URL cliente local")
    p.add_argument("--dst-ip",   type=str,  dest="dst_ip")
    p.add_argument("--dst-port", type=int,  dest="dst_port")
    p.add_argument("--proto",    type=str,  default="TCP", choices=["TCP","UDP"])
    p.add_argument("--msg",      type=str,  default="test")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.dst_ip and args.dst_port:
        send(args.client, args.dst_ip, args.dst_port, args.proto, args.msg)
    else:
        interactive(args.client)