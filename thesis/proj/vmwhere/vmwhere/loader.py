from cle.backends import Blob, register_backend
from archinfo import arch_from_id
import logging

l = logging.getLogger("cle.blob")

__all__ = ('VMWHERE',)

class VMWHERE(Blob):
    """
    Representation of a binary blob, i.e. an executable in an unknown file format.
    """
    is_default = True

    def __init__(self, *args, offset=3, **kwargs):
        """
        Loader backend for VMWHERE programs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        """
        super(VMWHERE, self).__init__(*args,
                arch=arch_from_id("vmwhere"),
                offset=offset,
                entry_point=0,
                **kwargs)
        self.os = "vmwhere"

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        stuff = stream.read(0x3)
        if stuff == b'WH\x42':
            return True
        return False

register_backend("vmwhere", VMWHERE)
