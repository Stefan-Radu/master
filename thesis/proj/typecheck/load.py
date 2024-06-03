from cle.backends import Blob, register_backend
from archinfo import arch_from_id
import logging

l = logging.getLogger("cle.blob")

__all__ = ('TC_UMD_24',)

class TC_UMD_24(Blob):
    """
    Representation of a binary blob, i.e. an executable in an unknown file format.
    """
    is_default = True
    header_size = 3

    def __init__(self, *args, offset=0x100, **kwargs):
        """
        Loader backend for BF programs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        """
        super(TC_UMD_24, self).__init__(*args,
                arch=arch_from_id('tc_umd_24'),
                offset=offset,
                entry_point=self.header_size,
                **kwargs)
        self.os = "tc_umd_24"

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        stuff = stream.read(TC_UMD_24.header_size)
        return stuff == b'\x42TC'

register_backend("tc_umd_24", TC_UMD_24)
