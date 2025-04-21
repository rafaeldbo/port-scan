# **port-scan**

`Port Scan` desenvolvido em `python` para a disciplina de Tecnologias Hacker (Insper 2025.1).

## **Funcionalidades**
- Suporte à `IPv4`
- Suporte à `IPv6`
- Escaneamento de rede
- Seleção personalizada de portas
- Identificação de `OS` via `Banner Grabbing`
- Nomeação de portas `Well Know Ports`
- Identificação do estado da porta

## **Como Instalar**
Faça a instalação diretamente em seu terminal por meio do `pip`

```
pip install git+https://github.com/rafaeldbo/port-scan
```
⚠️ **AVISO** ⚠️

Este programa foi desenvolvido utilizando **Python 3.13**, por isso, pode não funcionar corretamente para versões anteriores,

## **Como Utilizar**
Esse programa funciona apenas por linha de comando, utilize o comando a baixo para executar:
```
$ portscan [-h] [-a | -p PORTS | -r RANGE | -k] [--open] [--os] [-n N_THREADS] [-t TIMEOUT] [-v VALIDATION_PORTS] ip
```
### **Parâmetros**
-  `ip`: é o único parâmetro obrigatório e corresponde ao ip que será escaneado. Esse ip pode ser tando `IPv4` quanto `IPv6`. É possível fornecer, também, por meio desse parâmetro um `ip de rede`, com isso o programa irá escanear toda a rede correspondente ao `ip de rede` fornecido.
        
            EX.: portscan -k 192.168.0.0/24

### **Flags e Argumentos Opcionais**
- Para informar quais portas devem ser escaneadas utilize *apenas uma* das flags abaixo:
        
    - `-a` ou `--all`: escaneia todas as portas (de 0 a 65535, inclusive)
    - `-p` ou `--ports`: permite escolher uma lista de portas (cada porta separada por uma vírgula) para serem escaneadas
        ```
            EX.: portscan -p 22,80,443 192.168.0.2
        ```
    - `-r` ou `--range`: permite escolher um range de portas a ser escaneado, informando o range no formato {primeira}-{útima}
        ```
            EX.: portscan -r 0-1024 192.168.0.2
        ```   
    - `-k`: escaneia todas as `Well Know Ports` registradas no arquivo [wellKnowPorts.json](./app/wellKnowPorts.json)

- `--open`: instrui o programa a mostrar apenas as mensagens informando quais portas estão *abertas* (ocultando as mensagens das portas fechadas ou filtradas)
- `--os`: instrui o programa a tentar identificar qual é o sistema operacional do **host alvo** utilizando a tecnica de `Banner Grabbing`. Nessa tecnica, uma requisição falta será enviada para todas as portas ativas do host esperando que a resposta possua algum **banner** que indique seu sistema operacional
- `-n` ou `--n-threads`: permite alterar o número de **Threads** que serão utilizadas pelo processo de escaneamento ou de identificação de hosts da rede. Por padrão são utilizadas **32 Threads**.
- `-t` ou `--timeout`: permite alterar o tempo máximo de tentativa de conexão em uma porta. Utilizar um tempo de *timeout* pode permitir identificar mais portas abertas, porém pode deixar o escaneamento muito mais lento. o tempo padrão veria conforme o sistema operacional, sendo **3 segundos** se você estiver utilizando em um Windows e **1 segundo** nos demais OS
- `-v` ou `--validation-ports`: permite informar quais portas serão as portas (cada porta separada por uma vírgula) utilizadas para identificar se um host está ativo ou não. Esse argumento só é utilizado quando se está escaneando uma rede. Alterar esse argumento pode ser útil para identificar diferentes hosts que possam estar com um firewall ativo para determinadas portas. A porta padrão para essa validação é a **135**


## **Desenvolvedor**

- Rafael Dourado Bastos de Oliveira [[Linkedin]](https://www.linkedin.com/in/rafael-dourado-rdbo/)