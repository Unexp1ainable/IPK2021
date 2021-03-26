import argparse
from os import device_encoding
import os
from pathlib import Path
import socket
from sys import stderr

class ExceptionWithMessage(Exception):
    def __init__(self, message = "") -> None:
        self.message = message
        
class BadRequestException(ExceptionWithMessage):
    pass

class NotFoundException(ExceptionWithMessage):
    pass

class ServerErrorException(ExceptionWithMessage):
    pass

class InvalidFormatException(Exception):
    pass

class NotRecognizedException(ExceptionWithMessage):
    pass

class MissingCRLFException(Exception):
    pass

class InvalidHeaderException(Exception):
    pass

class InvalidProtocolException(Exception):
    pass

def parse_arguments():
    """Parse arguments from CLI

    Returns:
        populated namespace: Namespace filled with parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Program for IPK classes.")
    parser.add_argument("-n", required=True, help="Nameserver")
    parser.add_argument("-f", required=True, help="SURL")

    return parser.parse_args()


def parse_SURL(surl: str):
    """Splits SURL to 3 protocol, server and path substrings. Thows a ValueError exception if SURL is not valid.

    Args:
        surl (str): String representing whole SURL

    Returns:
        (str, str, str): Protocol, server and path substrings in tuple
    """
    protocol, address = surl.split("://", maxsplit=1)
    server, path = address.split("/", maxsplit=1)
    return protocol, server, path


def parse_address(nameserver: str):
    """Splits address of the nameserver to ip and port. Throws ValueError if invalid.

    Args:
        nameserver (str): Address and port of the server in ip_address:port format.

    Returns:
        (str, int): Tuple containing (ip, port)
    """
    ip, port = nameserver.split(":", maxsplit=1)
    return (ip, int(port))

def eprint(to_print: str):
    """Prints string to STDERR

    Args:
        to_print (str): String to print
    """
    print(to_print, file=stderr)


def receive_line(client: socket) -> str:
    """Recieves one line ending with CRLF from given TCP socket

    Args:
        client (socket): Socket to communicate on

    Raises:
        MissingCRLFException: If line did not end with CRLF

    Returns:
        str: Line contents stripped of CRLF
    """
    received = client.recv(1)
    line = b""


    while received != b"\r" and received != b"":
        line += received
        received = client.recv(1)

    received = client.recv(1)

    if received != b"\n":
        raise MissingCRLFException

    return line.decode(ENCODING)


def process_response(file_path: str, response_status: str, content: str):
    """Processes response from server and throws appropriate exception if necessary

    Args:
        file_path (str): Path to file requested
        response_status (str): Success, Bad Request, Not Found, Server Error
        content (str): Contents of the response

    Raises:
        BadRequestException
        NotFoundException
        ServerErrorException
        NotRecognizedException
    """
    if response_status == "Bad Request":
        raise BadRequestException(content)
    
    elif response_status == "Not Found":
        raise NotFoundException(content)
    
    elif response_status == "Server Error":
        raise ServerErrorException(content)
    
    elif response_status == "Success":
        return

    else:
        raise InvalidFormatException(content)



def get_file(fileserver_name: str, file_path: str, fileserver_address: str):
    """Establishes connection with the fileserver and attempts to receive file.

    Args:
        fileserver_name (str): Name of the fileserver
        file_path (str): Path to file on the fileserver
        fileserver_address (str): IP address of the fileserver

    Raises:
        InvalidHeaderException
        InvalidProtocolException
        InvalidFormatException
        BadRequestException
        NotFoundException
        ServerErrorException
        NotRecognizedException

    Returns:
        str: contents of the response
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(fileserver_address)
    client.settimeout(5.0)

    message = assemble_message(fileserver_name, file_path)

    client.send(message)
    statusline = receive_line(client)

    try:
        response_protocol, response_status = statusline.strip().split(maxsplit=1)
    except ValueError:
        raise InvalidHeaderException

    if response_protocol != "FSP/1.0":
        raise InvalidProtocolException

    try:
        length = int(receive_line(client)[7:])
    except:
        raise InvalidFormatException

    if receive_line(client) != "":
        raise InvalidFormatException

    content = b""
    for _ in range(length):
        content += client.recv(length)

    content = content.decode(ENCODING)
    process_response(file_path, response_status, content)
    return content



def assemble_message(fileserver_name: str, file_path: str) -> bytes:
    """Constructs a message for FSP to retrieve a file

    Args:
        fileserver_name (str): Name of the fileserver
        file_path (str): Path to file

    Returns:
        bytes: Encoded message to be sent
    """
    message = f"GET {file_path} FSP/1.0\r\n"
    message += f"Hostname: {fileserver_name}\r\n"
    message += f"Agent: xrepka07\r\n\r\n"
    message = message.encode()
    return message



def nsp_request(fileserver_name: str, nameserver_addr: str) -> str:
    """Requests IP address of the fileserver from nameserver using NSP

    Args:
        fileserver_name (str): Domain name
        nameserver_addr (str): IP address of the nameserver

    Raises:
        socket.timeout

    Returns:
        str: ip_address:port
    """

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = f"WHEREIS {fileserver_name}"
    client.sendto(message.encode(), nameserver_addr)
    client.settimeout(5.0)
    response = client.recv(54).decode()
    return response

def process_get_file_exceptions(e: Exception):
    """Prints description of error to stderr

    Args:
        e (Exception): Exception that occured
    """
    exception = e.__class__.__name__
    if exception == "InvalidHeaderException":
        eprint("[ERROR] Invalid response header.")
        exit(1)
    if exception == "InvalidProtocolException":
        eprint("[ERROR] Invalid protocol.")
        exit(1)
    if exception == "InvalidFormatException":
        eprint("[ERROR] Invalid format.")
        exit(1)
    if exception == "BadRequestException":
        eprint("[ERROR] File request failed.")
        eprint("Error message:")
        eprint(e.message)
        exit(1)
    if exception == "NotFoundException":
        eprint(f"[ERROR] File was not found on the server.")
        eprint("Error message:")
        eprint(e.message)
        exit(1)
    if exception == "ServerErrorException":
        eprint("[ERROR] Server could not comply.")
        eprint("Error message:")
        eprint(e.message)
        exit(1)
    if exception == "NotRecognizedException":
        eprint(f"Message not recognized.")
        eprint("Message contents:")
        eprint(e.message)
        exit(1)

def dump_file(content: str, name: str):
    Path(os.path.dirname(name)).mkdir(parents=True, exist_ok=True)
    with open(name, "w") as file:
        file.write(content)

if __name__ == "__main__":

    ENCODING = "utf-8"
    args = parse_arguments()

    try:
        protocol, fileserver_name, file_path = parse_SURL(args.f)
    except ValueError:
        eprint("[ERROR] Invalid SURL.")
        exit(1)

    try:
        nameserver_addr = parse_address(args.n)
    except ValueError:
        eprint("[ERROR] Invalid nameserver address.")
        exit(1)


    try:
        response = nsp_request(fileserver_name, nameserver_addr)
    except socket.timeout:
        eprint("[ERROR] Connection has timed out.")
        exit(1)

    if response[0:3] == "ERR":
        if response[4:] == "Syntax":
            eprint("[ERROR] Invalid FSP server address.")
        else:
            eprint("[ERROR] FSP server not found.")
        exit(1)

    if response[0:2] != "OK":
        eprint("[ERROR] Invalid nameserver response.")
        exit(1)

    try:
        fileserver_address = parse_address(response[3:])
    except ValueError:
        eprint("[ERROR] Invalid nameserver response.")
        exit(1)

    if file_path != "*":
        try:
            contents = get_file(fileserver_name, file_path, fileserver_address)
        except Exception as e:
            process_get_file_exceptions(e)

        dump_file(contents, file_path)

    else:
        pass
        contents = get_file(fileserver_name, "index", fileserver_address)

        files = contents.strip().split("\r\n")

        for file in files:
            try:
                contents = get_file(fileserver_name, file, fileserver_address)
            except Exception as e:
                process_get_file_exceptions(e)
            dump_file(contents, file)

