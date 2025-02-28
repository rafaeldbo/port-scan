import os, sys, argparse, signal
import json, time
import socket, ipaddress 

from utils import Console, parse_ip_version, parse_port_request, identify_os_banner
from multi_threading import multi_thread_pool, get_batches

def signal_handler(sig, frame):
    print("\nCtrl+C identificado, encerrando...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

ALL_PORTS = list(range(1,65535+1))
TIMEOUT = 3 if os.name == "nt" else 1
N_THREADS = 32
DEFAULT_VALIDATION_PORT = 135

wkp:dict[str, str] = json.load(open("wellKnowPorts.json"))
Console.wkp = wkp
            
def validate_host(ip:str, port:int=DEFAULT_VALIDATION_PORT) -> str:
    try:
        host_data = socket.getaddrinfo(ip, None)[0]
        host, family = host_data[4][0], host_data[0]
        with socket.socket(family, socket.SOCK_STREAM) as s:   
            s.settimeout(TIMEOUT)
            s.connect((host, port))
        return (host, family, "ativo")
    except socket.gaierror:
        return (ip, 0, "inválido")
    except TimeoutError:
        return (host, family, "não responde")  
    except (PermissionError, ConnectionRefusedError, OSError) as e:
        return (host, family, "ativo")    
            

def scan_port(host:str, port:int, family:int, timeout:float=TIMEOUT) -> None:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host,int(port)))
        return (port, "aberta")
    except (TimeoutError, ConnectionRefusedError, OSError):
        return (port, "fechada")
    except PermissionError:
        return (port, "filtrada")
    

def banner_grabbing(ip:str, port:int, family:int) -> str|None:
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        s.send(parse_port_request.get(port, b""))
        banner = s.recv(1024)
        return banner.decode().strip().lower()
    except Exception as e:
        pass
    finally:
        s.close()
        

def main():
    parser = argparse.ArgumentParser(
                    description="Permite que você escaneie portas de um host ou de uma rede",
                    epilog="Use com moderação")
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("ip",                       action="store",      help="Digite o endereço ip ou domínio")
    group.add_argument("-a",  "--all",              action="store_true", help="Realiza um scan em todas as ports")
    group.add_argument("-p",  "--ports",            action="store",      help="Especifique as ports, separando por virgula EX.: 80,5432,8080")
    group.add_argument("-r",  "--range",            action="store",      help="Especifique um range de portas a serem escaneadas, início e fim (inclusive) separandos por hífen EX.: 1-1024")
    group.add_argument("-k",  "--wellknowports",    action="store_true", help=f"Realiza um scan nas {len(wkp)} Well Know Ports registradas")
    parser.add_argument(      "--open",             action="store_true", help="Exibe apenas as ports abertas")
    parser.add_argument(      "--os",               action="store_true", help="Tenta identificar o sistema operacional via Banner Grabbing")
    parser.add_argument("-n", "--n-threads",        action="store",      help=f"Especifique o número de threads a serem utilizados (padrão: {N_THREADS})", type=int, default=N_THREADS)
    parser.add_argument("-t", "--timeout",          action="store",      help=f"Especifique o tempo de timeout (padrão: {TIMEOUT}s)", type=float, default=TIMEOUT)
    parser.add_argument("-v", "--validation-ports", action="store",      help=f"Especifique portas, separando por virgula, para serem utilizadas na validação dos hosts da rede (padrão: {DEFAULT_VALIDATION_PORT}) EX.: 22,80,135,445", default=str(DEFAULT_VALIDATION_PORT))
    args = parser.parse_args()

    family = 0
    host_list = []
    try:
        if "/" in args.ip:
            try:
                ipnet = ipaddress.ip_network(args.ip, strict=False)
                family = parse_ip_version[ipnet.version]
            except:
                print("Máscara de rede inválida")
                sys.exit(1)
                
            Console.print(f"\nEscaneando a rede {ipnet.netmask}")
            
            possible_hosts = [str(ip) for ip in ipnet.hosts()]
            validation_ports = [int(port) for port in args.validation_ports.split(",")]
            for port in validation_ports:
                arg_list = [(str(ip), port) for ip in possible_hosts]
                for arg_batch in get_batches(arg_list, args.n_threads):
                    result = multi_thread_pool(validate_host, arg_batch, args.n_threads)
                    
                    result = list(map(lambda x: x[0], filter(lambda x: x[2] == "ativo", result)))
                    result.sort(key=lambda x: int("".join(x.split("."))))
                    host_list += result
                    for host in result:
                        Console.print(f"host {host:<15} encontrado ativo na rede", "green")
                        possible_hosts.remove(host)

            if len(host_list) == 0:
                Console.print(f"Nenhum host válido encontrado com a máscara {ipnet.netmask}", "red")
                sys.exit(1)
        else:
            host, family, status = validate_host(args.ip)
            if status == "inválido":
                Console.print(f"Host {host} {status}", "red")
                sys.exit(1)
            host_list = [host]
            
        # Determinando as portas a serem escaneadas
        port_list = []
        if args.wellknowports:
            port_list = [int(port) for port in wkp.keys()]
        elif args.ports:
            port_list = [int(port) for port in args.ports.split(",")]
        elif args.range:
            port_range = args.range.split("-")
            port_list = list(range(int(port_range[0]), int(port_range[1])+1))
        elif args.all:
            port_list = ALL_PORTS
        else:
            Console.print("ERRO: Não foi especificado quais portas devem ser escaneadas", "red")
            sys.exit(1)
        
        for host in host_list:
            Console.print(f"\nEscaneando o host: {host}")
            arg_list = [(host, port, family, args.timeout) for port in port_list]
            
            # Realizando o scan
            Console.state_whitelist = ["aberta"] if args.open else ["aberta", "fechada", "filtrada"]
            start_time = time.time()
            
            scan_result = []
            for arg_batch in get_batches(arg_list, args.n_threads):
                result = multi_thread_pool(scan_port, arg_batch, args.n_threads)
                result.sort(key=lambda x: x[0])
                for port, state in result:
                    Console.port_log(port, state)
                scan_result += result
                    
            end_time = time.time()
            open_ports = list(map(lambda x: x[0], filter(lambda x: x[1] == "aberta", scan_result))) 
            close_ports = list(map(lambda x: x[0], filter(lambda x: x[1] == "fechada", scan_result)))
            filtered_ports = list(map(lambda x: x[0], filter(lambda x: x[1] == "filtrada", scan_result)))
            if args.open and len(open_ports) == 0:
                Console.print("Nenhuma porta aberta encontrada", "red")
            Console.print(f"{len(arg_list)} portas escaneadas em {end_time-start_time:.2f} segundos")
            Console.print(f"Resultado do escaneamento:\n{len(open_ports):>5} portas abertas\n{len(close_ports):>5} portas fechadas\n{len(filtered_ports):>5} portas filtradas")
            
            if args.os:
                banner_list = set()
                for port in open_ports:
                    banner = banner_grabbing(host, port, family)
                    os_identified = identify_os_banner(banner)
                    if os_identified is not None:
                        banner_list.add(os_identified)
                if len(banner_list) > 0:
                    os_identified = " | ".join(banner_list)
                    Console.print(f"Sistema Operacional do host identificado como: {os_identified}", "green")
                else:
                    Console.print("Não foi possível identificar o sistema Operacional do host", "red")
    except Exception as e:
        Console.print(e, "red")

if __name__ == "__main__":
    main()