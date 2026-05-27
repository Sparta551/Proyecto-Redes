from flask import Flask, request, jsonify, render_template
from datetime import datetime
import json, os, socket, requests as req

app = Flask(__name__)

RULES_FILE = "reglas.json"
clients    = {}
events     = []
logs       = []

# ══════════════════════════════════════
# REGLAS
# ══════════════════════════════════════
def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def save_rules():
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=4)

rules = load_rules()


def add_log(msg):
    entry = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "message": msg}
    logs.append(entry)
    print(f"[LOG] {entry['timestamp']} {msg}")


# ══════════════════════════════════════
# EVALUACIÓN
# ══════════════════════════════════════
def evaluate(src_ip, dst_ip, dst_port, protocol):
    ordered = sorted(rules, key=lambda x: x.get("priority", 0), reverse=True)

    print(f"\n[EVAL] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol}")
    print(f"[EVAL] Reglas activas: {len(ordered)}")

    for rule in ordered:
        r_src   = rule.get("src_ip",  "*")
        r_dst   = rule.get("dst_ip",  "*")
        r_port  = str(rule.get("dst_port", "*"))
        r_proto = rule.get("protocol", "*").upper()

        src_match   = r_src   == "*" or r_src   == src_ip
        dst_match   = r_dst   == "*" or r_dst   == dst_ip
        port_match  = r_port  == "*" or r_port  == str(dst_port)
        proto_match = r_proto == "*" or r_proto == protocol.upper()

        print(f"[EVAL] Regla #{rule['id']}: "
              f"src={r_src}({'✓' if src_match else '✗'}) "
              f"dst={r_dst}({'✓' if dst_match else '✗'}) "
              f"port={r_port}({'✓' if port_match else '✗'}) "
              f"proto={r_proto}({'✓' if proto_match else '✗'}) "
              f"→ {'HIT' if all([src_match,dst_match,port_match,proto_match]) else 'miss'}")

        if src_match and dst_match and port_match and proto_match:
            print(f"[EVAL] → {rule['action'].upper()} por regla #{rule['id']}\n")
            return rule["action"].upper(), rule["id"]

    print(f"[EVAL] → PERMIT (sin regla coincidente)\n")
    return "PERMIT", None


# ══════════════════════════════════════
# UI
# ══════════════════════════════════════
@app.route("/ui")
def ui():
    return render_template("server.html")


# ══════════════════════════════════════
# REGISTRO
# ══════════════════════════════════════
@app.route("/register", methods=["POST"])
def register():
    data     = request.get_json()
    node_ip  = data.get("ip", request.remote_addr)
    node_id  = data.get("id", node_ip)
    api_port = int(data.get("api_port", 8082))

    clients[node_ip] = {
        "id":        node_id,
        "ip":        node_ip,
        "api_port":  api_port,
        "status":    "active",
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    add_log(f"Nodo registrado: {node_id} @ {node_ip}  api:{api_port}")
    return jsonify({"status": "ok"})

@app.route("/clients")
def get_clients():
    return jsonify({"clients": list(clients.values())})


# ══════════════════════════════════════
# ENVÍO ENTRE NODOS
# ══════════════════════════════════════
@app.route("/send", methods=["POST"])
def send_message():
    data     = request.get_json()
    src_ip   = data.get("src_ip")
    dst_ip   = data.get("dst_ip")
    dst_port = int(data.get("dst_port"))
    protocol = data.get("protocol", "TCP").upper()
    message  = data.get("message", "")

    if dst_ip not in clients:
        return jsonify({"status": "ERROR",
                        "reason": f"Nodo {dst_ip} no registrado. "
                                  f"Registrados: {list(clients.keys())}"}), 400

    dst_node = clients[dst_ip]

    # ── EVALUAR REGLAS con la IP REAL del origen ──
    action, rule_id = evaluate(src_ip, dst_ip, dst_port, protocol)

    events.append({
        "src_ip":    src_ip,
        "src_port":  None,
        "dst_ip":    dst_ip,
        "dst_port":  dst_port,
        "protocol":  protocol,
        "action":    action,
        "rule_id":   rule_id,
        "message":   message,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    if action == "BLOCK":
        add_log(f"BLOQUEADO [#{rule_id}]: {src_ip} → {dst_ip}:{dst_port}/{protocol}")
        return jsonify({"status": "BLOCK",
                        "reason": f"Bloqueado por regla #{rule_id}"}), 403
    
    if action == "ALERT":
        add_log(f"ALERTA [#{rule_id}]: {src_ip} → {dst_ip}:{dst_port}/{protocol}")
        return jsonify({"status": "ALERT",
                        "reason": f"Alerta, usuario bloqueado por regla #{rule_id}"}), 403

    # Indicar al destino que abra el puerto
    api_url = f"http://{dst_ip}:{dst_node['api_port']}"
    try:
        req.post(f"{api_url}/open_port",
                 json={"port": dst_port, "protocol": protocol},
                 timeout=3)
        # Pequeña pausa para que el listener arranque
        import time; time.sleep(0.3)
    except Exception as e:
        add_log(f"WARN open_port {dst_ip}:{dst_port} — {e}")

    # Reenviar por socket — incluye src_ip en el payload para que
    # el destino sepa quién lo envió realmente
    add_log(f"PERMITIDO: {src_ip} → {dst_ip}:{dst_port}/{protocol} msg='{message}'")
    try:
        if protocol == "TCP":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((dst_ip, dst_port))
            # Formato: "FROM:<ip>|MSG:<mensaje>" para que el cliente pueda parsear el origen real
            payload = f"FROM:{src_ip}|MSG:{message}"
            s.send(payload.encode())
            reply = s.recv(4096).decode(errors="ignore")
            s.close()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            payload = f"FROM:{src_ip}|MSG:{message}"
            s.sendto(payload.encode(), (dst_ip, dst_port))
            try:
                reply, _ = s.recvfrom(4096)
                reply = reply.decode(errors="ignore")
            except socket.timeout:
                reply = "(sin respuesta UDP)"
            s.close()

        add_log(f"Respuesta de {dst_ip}: {reply}")
        return jsonify({"status": "PERMIT", "reply": reply, "from": dst_ip})

    except Exception as e:
        add_log(f"ERROR entregando a {dst_ip}:{dst_port} — {e}")
        return jsonify({"status": "ERROR",
                        "reason": f"No se pudo entregar a {dst_ip}:{dst_port} — {e}"}), 502


# ══════════════════════════════════════
# EVENTO
# ══════════════════════════════════════
@app.route("/event", methods=["POST"])
def receive_event():
    data = request.get_json()
    events.append({**data, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    return jsonify({"status": "ok"})


# ══════════════════════════════════════
# REGLAS CRUD
# ══════════════════════════════════════
@app.route("/rules")
def get_rules():
    return jsonify(rules)

@app.route("/add_rule", methods=["POST"])
def add_rule():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Datos requeridos"}), 400
    for f in ["src_ip", "dst_port", "protocol", "action", "priority"]:
        if f not in data:
            return jsonify({"error": f"Falta campo: {f}"}), 400
    rule = {
        "id":         len(rules) + 1,
        "src_ip":     data["src_ip"],
        "dst_ip":     data.get("dst_ip", "*"),
        "dst_port":   str(data["dst_port"]),
        "protocol":   data["protocol"].upper(),
        "action":     data["action"].upper(),
        "priority":   int(data["priority"]),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    rules.append(rule)
    save_rules()
    add_log(f"Regla #{rule['id']}: {rule['action']} {rule['src_ip']}→{rule['dst_ip']}:{rule['dst_port']}/{rule['protocol']}")
    return jsonify({"status": "ok", "rule": rule})

@app.route("/delete_rule/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    global rules
    before = len(rules)
    rules  = [r for r in rules if r["id"] != rule_id]
    if len(rules) == before:
        return jsonify({"error": "No encontrada"}), 404
    save_rules()
    add_log(f"Regla #{rule_id} eliminada")
    return jsonify({"status": "ok"})


# ══════════════════════════════════════
# CONSULTAS
# ══════════════════════════════════════
@app.route("/event_log")
def event_log():
    return jsonify({"total": len(events), "events": events})

@app.route("/logs")
def get_logs():
    return jsonify({"total": len(logs), "logs": logs})

@app.route("/stats")
def stats():
    blocked = sum(1 for e in events if e.get("action") in ("BLOCK", "ALERT"))
    alerts = sum(1 for e in events if e.get("action") == "ALERT")
    return jsonify({
        "active_clients": len(clients),
        "total_rules":    len(rules),
        "total_events":   len(events),
        "blocked":        blocked,
        "alerts":         alerts,
        "permitted":      len(events) - blocked
    })


if __name__ == "__main__":
    print("=" * 40)
    print(" SERVIDOR SDN  →  :8080")
    print("=" * 40)
    app.run(host="0.0.0.0", port=8080, debug=True)