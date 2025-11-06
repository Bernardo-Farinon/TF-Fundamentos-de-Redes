import argparse
from pathlib import Path
import socket
import threading
import time

routing_table: dict[str, tuple[int, str]] = {}
neighbors: set[str] = set()
local_ip = ""
last_seen: dict[str, float] = {}
table_print_count = 0
PORT = 6000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print_lock = threading.Lock()
routing_lock = threading.Lock()


def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)


def print_routing_table():
    # Protege leitura da tabela e imprime de forma atômica
    with routing_lock:
        safe_print("\n==== TABELA DE ROTEAMENTO ====")
        safe_print("Destino\t\tMétrica\tPróximo Salto")
        for dest, (metric, next_hop) in sorted(routing_table.items()):
            safe_print(f"{dest}\t{metric}\t{next_hop}")
        safe_print("================================\n")


def read_neighbors(local_ip: str, neighbors_file: Path):
    # Monta vizinhos/tabela com lock
    with routing_lock:
        neighbors.clear()
        routing_table.clear()

        for line in neighbors_file.read_text().splitlines():
            ip = line.strip()
            if ip and ip != local_ip:
                neighbors.add(ip)
                routing_table[ip] = (1, ip)
                last_seen[ip] = time.time()

        # prints fora ou dentro do lock? Pode ser dentro (curto) para garantir consistência
        safe_print(f"[INFO] Roteador local: {local_ip}")
        safe_print(f"[INFO] Vizinhos diretos: {sorted(neighbors)}")

    print_routing_table()


def send_announce_router():
    msg = f"@{local_ip}".encode()
    # snapshot de vizinhos sob lock
    with routing_lock:
        neigh_copy = list(neighbors)

    for n in neigh_copy:
        sock.sendto(msg, (n, PORT))
    safe_print(f"[ENVIO] Mensagem de anúncio enviada aos vizinhos: {msg.decode()}")


def listen():
    while True:
        data, addr = sock.recvfrom(1024)
        msg = data.decode().strip()
        sender = addr[0]

        with routing_lock:
            last_seen[sender] = time.time()
        
        safe_print(f"\n[RECV RAW] de {sender}: {msg}")

        if msg == "":
            safe_print(f"\n[RECV] Tabela vazia de {sender} — removendo rotas aprendidas via ele.")
            with routing_lock:
                removed = False
                for dest in list(routing_table.keys()):
                    metric, next_hop = routing_table[dest]
                    if next_hop == sender and dest != sender:
                        del routing_table[dest]
                        removed = True

            if removed:
                safe_print(f"[ATUALIZAÇÃO] Rotas via {sender} removidas (por tabela vazia).")
                print_routing_table()
            continue


        if msg.startswith("@"):
            safe_print(f"\n[RECV] Anúncio de roteador {msg} de {sender}")

            with routing_lock:
                last_seen[sender] = time.time()

                if sender not in neighbors:
                    neighbors.add(sender)
                    safe_print(f"[TOPOLOGIA] Novo vizinho detectado: {sender}")

                if sender not in routing_table or routing_table[sender][0] != 1:
                    routing_table[sender] = (1, sender)
                    safe_print(f"[REDETECT] Rota direta (1, {sender}) garantida.")

            print_routing_table()
            continue

        if msg.startswith("*"):
            safe_print(f"\n[RECV ROTAS] de {sender}: {msg}")
            process_route_message(sender, msg)
            continue

        if msg.startswith("!"):
            try:
                _bang, origem, destino, texto = msg.replace("!", "", 1).split(";", 3)
            except:
                safe_print(f"[RECV] Mensagem de texto mal formatada de {sender}: {msg}")
                continue

            if destino == local_ip:
                safe_print(f"\n[MENSAGEM DE {origem}] {texto}\n")
            else:
                # ler rota sob lock
                with routing_lock:
                    if destino not in routing_table:
                        missing = True
                        next_hop = None
                    else:
                        missing = False
                        next_hop = routing_table[destino][1]

                if missing:
                    safe_print(f"[ERRO] Recebida msg para {destino}, mas não há rota. Descartando.")
                    continue

                sock.sendto(msg.encode(), (next_hop, PORT))
                safe_print(f"[FORWARD] Encaminhando msg para {destino} via {next_hop}")
            continue

        safe_print(f"\n[RECV] Mensagem desconhecida de {sender}: {msg}")


def build_message_for_neighbor(neighbor: str) -> bytes:
    parts = []
    with routing_lock:
        for dest, (metric, next_hop) in routing_table.items():
            if dest == local_ip:
                continue
            if next_hop == neighbor:
                continue
            parts.append(f"*{dest};{metric}")

    return "".join(parts).encode()


def sender_loop():
    while True:
        # snapshot de vizinhos sob lock para não iterar estrutura mutável
        with routing_lock:
            neigh_copy = list(neighbors)

        for n in neigh_copy:
            payload = build_message_for_neighbor(n)
            sock.sendto(payload, (n, PORT))
            safe_print(f"[ENVIO] para {n}: {payload.decode() if payload else '(vazio)'}")

        time.sleep(10)


def process_route_message(sender_ip: str, payload: str):
    safe_print(f"[PROCESSANDO ROTAS] payload recebido de {sender_ip}: {payload}")
    changed = False

    entries = [p for p in payload.split("*") if p]
    announced_now = set()

    with routing_lock:
        # Garante vizinho e rota direta
        neighbors.add(sender_ip)
        if sender_ip not in routing_table or routing_table[sender_ip][0] != 1 or routing_table[sender_ip][1] != sender_ip:
            routing_table[sender_ip] = (1, sender_ip)
            changed = True

        for entry in entries:
            try:
                dest, metric_str = entry.split(";")
                metric = int(metric_str)
            except:
                safe_print(f"[WARN] entrada inválida no payload de {sender_ip}: {entry}")
                continue

            safe_print(f"  parsing -> destino: {dest}, métrica recebida: {metric} (vou armazenar como {metric+1} via {sender_ip})")

            if dest == local_ip:
                continue

            announced_now.add(dest)
            new_metric = metric + 1

            if dest not in routing_table:
                routing_table[dest] = (new_metric, sender_ip)
                changed = True
                safe_print(f"  [DEBUG] rota adicionada: {dest} -> {(new_metric, sender_ip)}")
                continue

            current_metric, current_next = routing_table[dest]
            if new_metric < current_metric:
                routing_table[dest] = (new_metric, sender_ip)
                changed = True

        # NÃO remova a rota direta para o visinho (dest == sender_ip)
        routes_via_sender = {
            dest for dest, (m, nh) in routing_table.items()
            if nh == sender_ip and dest != sender_ip
        }
        missing = routes_via_sender - announced_now
        for dest in missing:
            del routing_table[dest]
            changed = True

    if changed:
        safe_print(f"\n[ATUALIZAÇÃO] Tabela atualizada a partir de {sender_ip}")
        print_routing_table()



def timeout_monitor():
    while True:
        now = time.time()

        # snapshot de candidatos inativos
        with routing_lock:
            stale = []
            for n in list(neighbors):
                if n in last_seen and now - last_seen[n] > 15:
                    stale.append(n)

        for n in stale:
            safe_print(f"\n[TIMEOUT] Vizinho {n} inativo! Removendo rotas dependentes...")

            with routing_lock:
                removed = False

                if n in routing_table:
                    del routing_table[n]
                    removed = True

                # Remover rotas que dependiam desse next_hop
                for dest in list(routing_table.keys()):
                    _, next_hop = routing_table[dest]
                    if next_hop == n:
                        del routing_table[dest]
                        removed = True

                neighbors.discard(n)
                last_seen.pop(n, None)

            if removed:
                print_routing_table()

        time.sleep(1)


def periodic_table_display():
    global table_print_count
    while True:
        time.sleep(15)
        table_print_count += 1
        safe_print(f"\n[INFO] Exibindo tabela periodicamente (vez #{table_print_count}):")
        print_routing_table()


def send_text_message(dest: str, text: str):
    msg = f"!{local_ip};{dest};{text}".encode()

    with routing_lock:
        if dest not in routing_table:
            missing = True
            next_hop = None
        else:
            missing = False
            next_hop = routing_table[dest][1]

    if missing:
        safe_print(f"[ERRO] Não existe rota para {dest}. Mensagem descartada.")
        return

    sock.sendto(msg, (next_hop, PORT))
    safe_print(f"[ENVIO MSG] Para {dest} via {next_hop}: {text}")


def user_input_loop():
    while True:
        try:
            line = input().strip()
        except EOFError:
            return

        if not line.startswith("send "):
            safe_print("[USO] send <dest_ip> <mensagem>")
            continue

        try:
            _, dest, text = line.split(" ", 2)
        except:
            safe_print("[USO] send <dest_ip> <mensagem>")
            continue

        send_text_message(dest, text)


def main():
    global local_ip
    parser = argparse.ArgumentParser(description="Roteador - Parte 1")
    parser.add_argument("local_ip", type=str, help="IP local deste roteador")
    parser.add_argument("neighbors_file", type=Path, help="Arquivo de vizinhos")
    args = parser.parse_args()

    local_ip = args.local_ip

    read_neighbors(local_ip, args.neighbors_file)

    sock.bind((local_ip, PORT))
    safe_print(f"[BOOT] Socket UDP ativo em {local_ip}:{PORT}")

    threading.Thread(target=listen, daemon=True).start()
    send_announce_router()

    threading.Thread(target=sender_loop, daemon=True).start()
    threading.Thread(target=timeout_monitor, daemon=True).start()
    threading.Thread(target=periodic_table_display, daemon=True).start()
    threading.Thread(target=user_input_loop, daemon=True).start()

    safe_print("\n[ENTER] para encerrar.\n")
    input("")


if __name__ == "__main__":
    main()
