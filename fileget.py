import argparse
import os
from pathlib import Path
import socket
from sys import stderr
from traceback import print_exc

class ExceptionWithMessage(Exception):
    def __init__(self, message = "") -> None:
        self.message = message
        
class BadRequestException(ExceptionWithMessage):
    pass

class NotFoundException(ExceptionWithMessage):
    pass

class ServerErrorException(ExceptionWithMessage):
    pass
class NotRecognizedException(ExceptionWithMessage):
    pass

class InvalidFormatException(Exception):
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
    parser.add_argument("-n", required=True, help="Nameserver.")
    parser.add_argument("-f", required=True, help="SURL.")
    parser.add_argument("-d", "--debug", action="store_true", help="Prints files to stdin instead of creating new file.")

    return parser.parse_args()


def parse_SURL(surl: str):
    """Splits SURL to protocol, server and path substrings.

    Args:
        surl (str): String representing whole SURL
    
    Raises:
        ValueError: if SURL is not valid

    Returns:
        (str, str, str): Protocol, server and path substrings in tuple
    """
    protocol, address = surl.split("://", maxsplit=1)
    server, path = address.split("/", maxsplit=1)
    return protocol, server, path


def parse_address(nameserver: str):
    """Splits address of the nameserver to ip and port.

    Args:
        nameserver (str): Address and port of the server in ip_address:port format.

    Raises:
        ValueError: if nameserver address is not valid

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


def receive_line(client: socket.socket) -> str:
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


def process_response(response_status: str, content: str):
    """Processes response from server and throws appropriate exception if necessary

    Args:
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



def get_file(fileserver_name: str, fileserver_address: str, file_path: str):
    """Establishes connection with the fileserver and attempts to receive file.

    Args:
        fileserver_name (str): Name of the fileserver
        fileserver_address (str): IP address of the fileserver
        file_path (str): Path to file on the fileserver

    Raises:
        InvalidHeaderException
        InvalidProtocolException
        InvalidFormatException
        BadRequestException
        NotFoundException
        ServerErrorException
        NotRecognizedException
        System exceptions about connection

    Returns:
        str: contents of the response
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(fileserver_address)
    message = assemble_FSP_message(fileserver_name, file_path)

    client.send(message)
    statusline = receive_line(client)

    # line should be: protocol status
    try:
        response_protocol, response_status = statusline.strip().split(maxsplit=1)
    except ValueError:
        raise InvalidHeaderException

    if response_protocol != "FSP/1.0":
        raise InvalidProtocolException

    # format of this line should be: Length: number
    try:
        length = int(receive_line(client)[7:]) 
    except ValueError:
        raise InvalidFormatException

    # next line should be empty
    if receive_line(client) != "":
        raise InvalidFormatException

    # rest should be contents of the message
    content = b""
    for _ in range(length):
        content += client.recv(length)

    content = content.decode(ENCODING)
    process_response(response_status, content)
    return content



def assemble_FSP_message(fileserver_name: str, file_path: str) -> bytes:
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
        eprint(f"[ERROR] Message not recognized.")
        eprint("Message contents:")
        eprint(e.message)
        exit(1)
    else:
        eprint(f"[ERROR] Connection failure.")
        eprint("Exception message:")
        eprint(str(e))
        exit(1)

def print_to_file(content: str, name: str, debug: bool):
    """Create file with folder structure if necessary and write content to it.

    Args:
        content (str): Content to be written into file
        name (str): path to file(including name of the file)
    """
    # create folder structure if necessary
    if not debug:
        Path(os.path.dirname(name)).mkdir(parents=True, exist_ok=True)
        with open(name, "w") as file:
            file.write(content)
    else:
        print(f"File: {name}")
        print(content)

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
        # Single file download
        try:
            contents = get_file(fileserver_name, fileserver_address, file_path)
        except Exception as e:
            process_get_file_exceptions(e)

        print_to_file(contents, file_path, args.debug)

    else:
        # Get all files
        try:
            contents = get_file(fileserver_name, fileserver_address, "index")
        except Exception as e:
            process_get_file_exceptions(e)

        files = contents.strip().split("\r\n")

        for file in files:
            try:
                contents = get_file(fileserver_name, fileserver_address, file)
            except Exception as e:
                process_get_file_exceptions(e)
            print_to_file(contents, file, args.debug)

