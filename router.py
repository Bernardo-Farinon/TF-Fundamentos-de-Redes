import argparse
from pathlib import Path

routing_table: dict[str, tuple[int, str]] = {}
neighbors: set[str] = set()

def read_neighbors(local_ip: str, neighbors_file: Path) -> None:
    neighbors.clear()
    routing_table.clear()

    lines = [l.strip() for l in neighbors_file.read_text().splitlines() if l.strip()]
    for ip in lines:
        if ip == local_ip:
            continue  # não adiciona rota para ele mesmo
        neighbors.add(ip)

    # Inicializa tabela: custo = 1, saída = o próprio vizinho
    for n in neighbors:
        routing_table[n] = (1, n)

def print_routing_table() -> None:
    print("\nRouting Table Inicial:")
    print("----------------------")
    for dest, (cost, next_hop) in routing_table.items():
        print(f"Destino: {dest} | Custo: {cost} | Próximo Salto: {next_hop}")
    print()

def main() -> None:
    parser = argparse.ArgumentParser(description="Simple Router")
    parser.add_argument("local_ip", type=str, help="IP local do roteador")
    parser.add_argument("neighbors_file", type=Path, help="Arquivo contendo IPs dos vizinhos")
    args = parser.parse_args()

    read_neighbors(args.local_ip, args.neighbors_file)
    print_routing_table()

if __name__ == "__main__":
    main()
