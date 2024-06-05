from argparse import ArgumentParser
import tomli
import os
import stat
import logging

from render import *

log = logging.getLogger(__name__)

def parse_args():
    parser = ArgumentParser(prog='arch-genesys')

    gen_group = parser.add_argument_group(
        'Template Generation', 'Generate new template')
    gen_group.add_argument(
        '-t', '--template', action='store_true',
        help='Generate an empty config')
    gen_group.add_argument(
        '-n', '--name', default='default',
        help='Name of the generated config')

    parse_group = parser.add_argument_group(
        'Template Parsing', 'Parse a template and '\
        'generate the angr architecture package')
    parse_group.add_argument(
        '-c', '--config', help='Config file')
    parse_group.add_argument(
        '-o', '--output', help='Output directory name')

    return parser.parse_args()


def main():
    args = parse_args()
    if args.template:
        name=args.name
        # TODO 
    elif args.config:
        data = open(args.config, 'r').read()
        data_dict = tomli.loads(data)

        dir_path = args.output if args.output \
            else data_dict['arch']['name']

        try:
            os.mkdir(dir_path)
        except FileExistsError:
            log.error(f"Directory '{dir_path}' already exists. Overriding...")
            # return
        except OSError as e:
            log.error(f"Error creating directory '{dir_path}': {e}")
            # return

        rendered_package = {
            '__init__': render_init(data_dict),
            'arch':     render_arch(data_dict),
            'loader':   render_loader(data_dict),
            'lifter':   render_lifter(data_dict),
            'simos':    render_simos(data_dict),
        }

        # write angr architecture plugin
        for blob_name, blob in rendered_package.items():
            f = open(f'{os.path.join(dir_path, blob_name)}.py', 'w')
            f.write(blob)
            f.close()

        # write disassembler
        disass_path = os.path.join(dir_path, '..', 'disassemble')
        with open(disass_path, 'w') as f:
            f.write(render_disassembly(data_dict))
        # make disassembler executable
        st = os.stat(disass_path)
        os.chmod(disass_path, st.st_mode | stat.S_IEXEC)


if __name__ == '__main__':
    main()
