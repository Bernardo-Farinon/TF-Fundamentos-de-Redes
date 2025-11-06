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


def print_routing_table():
    print("\n==== TABELA DE ROTEAMENTO ====")
    print("Destino\t\tMétrica\tPróximo Salto")
    for dest, (metric, next_hop) in sorted(routing_table.items()):
        print(f"{dest}\t{metric}\t{next_hop}")
    print("================================\n")


def read_neighbors(local_ip: str, neighbors_file: Path):
    neighbors.clear()
    routing_table.clear()

    for line in neighbors_file.read_text().splitlines():
        ip = line.strip()
        if ip and ip != local_ip:
            neighbors.add(ip)
            routing_table[ip] = (1, ip)
            last_seen[ip] = time.time()

    print(f"[INFO] Roteador local: {local_ip}")
    print(f"[INFO] Vizinhos diretos: {sorted(neighbors)}")
    print_routing_table()


def send_announce_router():
    msg = f"@{local_ip}".encode()
    for n in neighbors:
        sock.sendto(msg, (n, PORT))
    print(f"[ENVIO] Mensagem de anúncio enviada aos vizinhos: {msg.decode()}")


def listen():
    while True:
        data, addr = sock.recvfrom(1024)
        msg = data.decode().strip()
        sender = addr[0]

        last_seen[sender] = time.time()

        if not msg:
            continue

        if msg.startswith("@"):
            print(f"\n[RECV] Anúncio de roteador {msg} de {sender}")

            last_seen[sender] = time.time()

            if sender not in neighbors:
                neighbors.add(sender)
                print(f"[TOPOLOGIA] Novo vizinho detectado: {sender}")

            if sender not in routing_table or routing_table[sender][0] != 1:
                routing_table[sender] = (1, sender)
                print(f"[REDETECT] Rota direta (1, {sender}) garantida.")

            print_routing_table()
            continue


        if msg.startswith("*"):
            process_route_message(sender, msg)
            continue

        if msg.startswith("!"):
            try:
                _bang, origem, destino, texto = msg.replace("!", "", 1).split(";", 3)
            except:
                print(f"[RECV] Mensagem de texto mal formatada de {sender}: {msg}")
                continue

            if destino == local_ip:
                print(f"\n[MENSAGEM DE {origem}] {texto}\n")
            else:
                if destino not in routing_table:
                    print(f"[ERRO] Recebida msg para {destino}, mas não há rota. Descartando.")
                    continue

                next_hop = routing_table[destino][1]
                sock.sendto(msg.encode(), (next_hop, PORT))
                print(f"[FORWARD] Encaminhando msg para {destino} via {next_hop}")
            continue

        print(f"\n[RECV] Mensagem desconhecida de {sender}: {msg}")



def build_message_for_neighbor(neighbor: str) -> bytes:
    parts = []

    for dest, (metric, next_hop) in routing_table.items():
        if dest == local_ip:
            continue

        if next_hop == neighbor:
            continue

        parts.append(f"*{dest};{metric}")

    return "".join(parts).encode()


def sender_loop():
    while True:
        for n in neighbors:
            payload = build_message_for_neighbor(n)

            sock.sendto(payload, (n, PORT))

            print(f"[ENVIO] para {n}: {payload.decode() if payload else '(vazio)'}")

        time.sleep(10)


def process_route_message(sender_ip: str, payload: str):
    changed = False

    entries = [p for p in payload.split("*") if p]

    announced_now = set()

    for entry in entries:
        try:
            dest, metric_str = entry.split(";")
            metric = int(metric_str)
        except:
            continue

        if dest == local_ip:
            continue

        announced_now.add(dest)

        new_metric = metric + 1

        if dest not in routing_table:
            routing_table[dest] = (new_metric, sender_ip)
            changed = True
            continue

        current_metric, current_next = routing_table[dest]
        if new_metric < current_metric:
            routing_table[dest] = (new_metric, sender_ip)
            changed = True

    routes_via_sender = {dest for dest, (m, nh) in routing_table.items() if nh == sender_ip}

    missing = routes_via_sender - announced_now

    for dest in missing:
        del routing_table[dest]
        changed = True

    if changed:
        print(f"\n[ATUALIZAÇÃO] Tabela atualizada a partir de {sender_ip}")
        print_routing_table()


def timeout_monitor():
    while True:
        now = time.time()
        for n in list(neighbors):
            if n not in last_seen:
                continue

            if now - last_seen[n] > 15:
                print(f"\n[TIMEOUT] Vizinho {n} inativo! Removendo rotas dependentes...")

                removed = False

                if n in routing_table:
                    del routing_table[n]
                    removed = True

                for dest in list(routing_table.keys()):
                    _, next_hop = routing_table[dest]
                    if next_hop == n:
                        del routing_table[dest]
                        removed = True

                if removed:
                    print_routing_table()

                last_seen[n] = now

        time.sleep(1)


def periodic_table_display():
    global table_print_count
    while True:
        time.sleep(15)
        table_print_count += 1
        print(f"\n[INFO] Exibindo tabela periodicamente (vez #{table_print_count}):")
        print_routing_table()


def send_text_message(dest: str, text: str):
    msg = f"!{local_ip};{dest};{text}".encode()

    if dest not in routing_table:
        print(f"[ERRO] Não existe rota para {dest}. Mensagem descartada.")
        return

    next_hop = routing_table[dest][1]
    sock.sendto(msg, (next_hop, PORT))
    print(f"[ENVIO MSG] Para {dest} via {next_hop}: {text}")


def user_input_loop():
    while True:
        try:
            line = input().strip()
        except EOFError:
            return

        if not line.startswith("send "):
            print("[USO] send <dest_ip> <mensagem>")
            continue

        try:
            _, dest, text = line.split(" ", 2)
        except:
            print("[USO] send <dest_ip> <mensagem>")
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
    print(f"[BOOT] Socket UDP ativo em {local_ip}:{PORT}")

    threading.Thread(target=listen, daemon=True).start()

    send_announce_router()

    threading.Thread(target=sender_loop, daemon=True).start()
    threading.Thread(target=timeout_monitor, daemon=True).start()
    threading.Thread(target=periodic_table_display, daemon=True).start()
    threading.Thread(target=user_input_loop, daemon=True).start()

    input("\n[ENTER] para encerrar.\n")


if __name__ == "__main__":
    main()
