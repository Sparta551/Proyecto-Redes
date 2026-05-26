import requests as req
import socket
import threading
import time
import json
import os
from flask import Flask, request, jsonify

# ══════════════════════════════════════
# CONFIG
# ══════════════════════════════════════
CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "server_url":        "http://192.168.0.10:8080",
    "api_port":          8082,   # puerto del API interno (solo para /send e /inbox)
    "register_interval": 10,
    "node_id":           socket.gethostname()
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
        return {**DEFAULT_CONFIG, **cfg}
    with open(CONFIG_FILE, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)
    return DEFAULT_CONFIG

config     = load_config()
SERVER_URL = config["server_url"]
API_PORT   = int(config["api_port"])
NODE_ID    = config["node_id"]
REGISTER_INTERVAL = config["register_interval"]

inbox = []   # mensajes recibidos


# ══════════════════════════════════════
# IP LOCAL
# ══════════════════════════════════════
def get_my_ip():
    try:
        host = SERVER_URL.split("//")[1].split(":")[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return socket.gethostbyname(socket.gethostname())

MY_IP = get_my_ip()


# ══════════════════════════════════════
# REGISTRO PERIÓDICO
# Solo informa IP — sin puerto fijo
# ══════════════════════════════════════
def register():
    try:
        req.post(
            f"{SERVER_URL}/register",
            json={"id": NODE_ID, "ip": MY_IP},
            timeout=5
        )
        print(f"[OK] Registrado: {NODE_ID} @ {MY_IP}  (sin puerto fijo)")
    except Exception as e:
        print(f"[ERR] Registro fallido: {e}")

def registration_loop():
    while True:
        register()
        time.sleep(REGISTER_INTERVAL)


# ══════════════════════════════════════
# GUARDAR MENSAJE RECIBIDO
# ══════════════════════════════════════
def store_message(src_ip, dst_port, protocol, raw_data):
    entry = {
        "from":      src_ip,
        "dst_port":  dst_port,
        "protocol":  protocol,
        "message":   raw_data,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    inbox.append(entry)
    print(f"\n{'='*46}")
    print(f"  MENSAJE RECIBIDO")
    print(f"  De        : {src_ip}")
    print(f"  En puerto : {dst_port}  ({protocol})")
    print(f"  Mensaje   : {raw_data}")
    print(f"{'='*46}\n")
    return entry


# ══════════════════════════════════════
# REENVIAR EVENTO AL SERVIDOR
# ══════════════════════════════════════
def report_event(src_ip, dst_port, protocol, action, message):
    try:
        req.post(
            f"{SERVER_URL}/event",
            json={
                "node_id":  NODE_ID,
                "src_ip":   src_ip,
                "dst_ip":   MY_IP,
                "dst_port": dst_port,
                "protocol": protocol,
                "action":   action,
                "message":  message
            },
            timeout=3
        )
    except Exception as e:
        print(f"[ERR] report_event: {e}")


# ══════════════════════════════════════
# LISTENER TCP — acepta en UN puerto
# Se lanza un hilo por cada puerto que
# el servidor le indica al reenviar
# ══════════════════════════════════════
active_tcp_ports = set()
active_udp_ports = set()
ports_lock = threading.Lock()

def handle_tcp_conn(conn, addr, port):
    src_ip = addr[0]
    try:
        data    = conn.recv(4096)
        message = data.decode(errors="ignore").strip()
        store_message(src_ip, port, "TCP", message)
        report_event(src_ip, port, "TCP", "PERMIT", message)
        conn.send(f"ACK de {NODE_ID} ({MY_IP}): recibí '{message}'".encode())
    except Exception as e:
        print(f"[ERR] handle_tcp_conn: {e}")
    finally:
        conn.close()

def listen_tcp_port(port):
    with ports_lock:
        if port in active_tcp_ports:
            return
        active_tcp_ports.add(port)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(10)
        sock.settimeout(300)   # 5 min sin actividad → cierra el listener
        print(f"[TCP] Escuchando en puerto {port}")
        while True:
            try:
                conn, addr = sock.accept()
                threading.Thread(
                    target=handle_tcp_conn,
                    args=(conn, addr, port),
                    daemon=True
                ).start()
            except socket.timeout:
                print(f"[TCP] Puerto {port} inactivo, cerrando listener")
                break
    except OSError as e:
        print(f"[ERR] TCP puerto {port}: {e}")
    finally:
        with ports_lock:
            active_tcp_ports.discard(port)


# ══════════════════════════════════════
# LISTENER UDP — acepta en UN puerto
# ══════════════════════════════════════
def listen_udp_port(port):
    with ports_lock:
        if port in active_udp_ports:
            return
        active_udp_ports.add(port)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.settimeout(300)
        print(f"[UDP] Escuchando en puerto {port}")
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip  = addr[0]
                message = data.decode(errors="ignore").strip()
                store_message(src_ip, port, "UDP", message)
                report_event(src_ip, port, "UDP", "PERMIT", message)
            except socket.timeout:
                print(f"[UDP] Puerto {port} inactivo, cerrando listener")
                break
    except OSError as e:
        print(f"[ERR] UDP puerto {port}: {e}")
    finally:
        with ports_lock:
            active_udp_ports.discard(port)


# ══════════════════════════════════════
# ABRIR PUERTO BAJO DEMANDA
# El servidor llama aquí antes de reenviar
# POST /open_port  { port, protocol }
# ══════════════════════════════════════
app = Flask(__name__)

@app.route("/open_port", methods=["POST"])
def open_port():
    data     = request.get_json()
    port     = int(data.get("port"))
    protocol = data.get("protocol", "TCP").upper()

    if protocol == "TCP":
        threading.Thread(target=listen_tcp_port, args=(port,), daemon=True).start()
    else:
        threading.Thread(target=listen_udp_port, args=(port,), daemon=True).start()

    return jsonify({"status": "ok", "port": port, "protocol": protocol})


# ══════════════════════════════════════
# /send  — trafic.py llama aquí
# Body: { dst_ip, dst_port, protocol, message }
# ══════════════════════════════════════
@app.route("/send", methods=["POST"])
def send():
    data     = request.get_json()
    dst_ip   = data.get("dst_ip")
    dst_port = int(data.get("dst_port"))
    protocol = data.get("protocol", "TCP").upper()
    message  = data.get("message", "")

    if not dst_ip or not dst_port:
        return jsonify({"error": "Faltan: dst_ip, dst_port"}), 400

    print(f"[→] {MY_IP} → {dst_ip}:{dst_port}/{protocol}  msg='{message}'")

    try:
        r = req.post(
            f"{SERVER_URL}/send",
            json={
                "src_ip":   MY_IP,
                "dst_ip":   dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "message":  message
            },
            timeout=8
        )
        result = r.json()
        if r.status_code == 403:
            print(f"[✗] BLOQUEADO: {result.get('reason','')}")
        elif r.status_code == 200:
            print(f"[✓] PERMITIDO — respuesta: {result.get('reply','')}")
        return jsonify(result), r.status_code

    except Exception as e:
        print(f"[ERR] /send: {e}")
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════
# /inbox
# ══════════════════════════════════════
@app.route("/inbox")
def get_inbox():
    return jsonify({
        "node":     NODE_ID,
        "ip":       MY_IP,
        "messages": inbox,
        "tcp_ports_open": sorted(active_tcp_ports),
        "udp_ports_open": sorted(active_udp_ports)
    })


# ══════════════════════════════════════
# MAIN
# ══════════════════════════════════════
if __name__ == "__main__":
    print("=" * 50)
    print(f"  NODO SDN  : {NODE_ID}")
    print(f"  IP        : {MY_IP}")
    print(f"  API local : {API_PORT}  (solo /send, /inbox, /open_port)")
    print(f"  Puertos de datos: dinámicos (abre al recibir mensajes)")
    print(f"  Servidor  : {SERVER_URL}")
    print("=" * 50)

    threading.Thread(target=registration_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=API_PORT, debug=False, use_reloader=False)