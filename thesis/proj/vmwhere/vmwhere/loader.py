from cle.backends import Blob, register_backend
from archinfo import arch_from_id
import logging

log = logging.getLogger("cle.loader")

__all__ = ('VMWHERE',)

class VMWHERE(Blob):
    """
    Representation of a binary blob, i.e. an executable in an unknown file format.
    """
    is_default = True

    def __init__(self, *args, offset=3, **kwargs):
        """
        Loader backend for vmwhere programs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        :param entry_point: start
        """
        super(VMWHERE, self).__init__(*args,
                arch=arch_from_id("vmwhere"),
                offset=offset,
                entry_point=0,
                base_addr=0,
                **kwargs)
        self.os = "vmwhere"

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        stuff = stream.read(3)
        header = bytes.fromhex(hex(5720130)[2:])
        if stuff == header:
            log.info(f"matched vmwhere")
            return True
        log.info(f"vmwhere NOT matched")
        return False

register_backend("vmwhere", VMWHERE)