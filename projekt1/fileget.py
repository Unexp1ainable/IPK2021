from funclib import ENCODING, eprint, get_file_fsp, nsp_request, parse_SURL, parse_address, parse_arguments, print_to_file, process_get_file_exceptions
import socket

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
        contents = get_file_fsp(fileserver_name, fileserver_address, file_path)
    except Exception as e:
        process_get_file_exceptions(e)

    print_to_file(contents, file_path, args.debug)

else:
    # Get all files
    try:
        contents = get_file_fsp(fileserver_name, fileserver_address, "index").decode(ENCODING)
    except Exception as e:
        process_get_file_exceptions(e)

    files = contents.strip().split("\r\n")

    for file in files:
        try:
            contents = get_file_fsp(fileserver_name, fileserver_address, file)
        except Exception as e:
            process_get_file_exceptions(e)
        print_to_file(contents, file, args.debug)

