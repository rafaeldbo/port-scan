import socket

class Console:
    state_whitelist = []
    wkp:dict[str, str]
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "cyan": "\033[96m",
        "purple": "\033[95m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
    }
    state_colors = {
        "filtrada": "\033[91m",
        "aberta": "\033[92m",
        "fechada": "\033[0m",
        "reset": "\033[0m",
    }
    reset_color = "\033[0m"
    
    def port_log(port:int, state:str) -> str:
        if state in Console.state_whitelist:
            port_name = Console.wkp.get(str(port), "")
            print(f"{Console.state_colors[state]}[TCP] {port:>5} {port_name:<14} {state:>8}{Console.reset_color}")

    def print(text:str, color:str="reset") -> None:
        color = color.strip().lower()
        print(f"{Console.colors[color]}{text}{Console.reset_color}") if color in Console.colors else print(text)

parse_ip_version = {
    4: socket.AF_INET,
    6: socket.AF_INET6,
}
parse_port_request = {
    21: b"USER anonymous\r\n",
    25: b"HELO test.com\r\n",
    80: b"HEAD / HTTP/1.1\r\nHost: anonymous.com\r\n\r\n",
    110: b"USER anonymous\r\n",
    143: b"LOGIN anonymous pass\r\n",
    443: b"HEAD / HTTP/1.1\r\nHost: anonymous.com\r\n\r\n",
}

def identify_os_banner(banner:str) -> str:
    if banner is None:
        return None
    if "windows" in banner or "microsoft" in banner:
        return "Windows"
    elif "linux" in banner:
        return "Linux"
    elif "debian" in banner:
        return "Debian"
    elif "ubuntu" in banner:
        return "Ubuntu"
    elif "centos" in banner:
        return "CentOS"
    elif "macos" in banner:
        return "MacOS"