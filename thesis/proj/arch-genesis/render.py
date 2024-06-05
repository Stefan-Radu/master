from jinja2 import FileSystemLoader, Environment
from datetime import datetime, UTC
import os


dirname = os.path.dirname(__file__)
template_folder_path = os.path.join(dirname, 'templates')
template_loader = FileSystemLoader(searchpath=template_folder_path)
template_env = Environment(loader=template_loader)
now_iso = datetime.now(UTC).isoformat()


def render_template(template_name: str, data = {}, **kwargs) -> str:
    template = template_env.get_template(template_name)
    return template.render(data, datetime=now_iso, **kwargs)

def render_disassembly(data):
    archname = data['arch']['name']
    return render_template('disassemble.py.jinja', archname=archname)

def render_init(data):
    archnameup = data['arch']['name'].upper()
    return render_template('__init__.py.jinja', archnameup=archnameup)

def render_arch(data):
    return render_template('arch.py.jinja', data['arch'])

def render_loader(data):
    archname = data['arch']['name']
    return render_template('loader.py.jinja', data['loader'],
                          archname=archname)

def render_lifter(data):
    for op, opdata in data['lifter']['opcodes'].items():
        bin_format = ''
        for xxx in opdata['bin_format']:
            if isinstance(xxx, int):
                bin_format += bin(xxx)[2:].zfill(8)
            elif isinstance(xxx, str):
                bin_format += xxx
            elif isinstance(xxx, list):
                assert(len(xxx) == 2)
                a, b = xxx
                assert(isinstance(a, str))
                assert(isinstance(b, int))
                bin_format += a * b
        data['lifter']['opcodes'][op]['bin_format'] = bin_format
    return render_template('lifter.py.jinja', data)

def render_simos(data):
    archname = data['arch']['name']
    arch = data['arch']
    return render_template('simos.py.jinja', data['simos'],
                          archname=archname, arch=arch)
