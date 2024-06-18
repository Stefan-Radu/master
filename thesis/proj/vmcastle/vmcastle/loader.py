from cle.backends import Blob, register_backend
from archinfo import arch_from_id
import logging

log = logging.getLogger("cle.loader")

__all__ = ('VMCASTLE',)

class VMCASTLE(Blob):
    """
    Representation of a binary blob, i.e. an executable in an unknown file format.
    """
    is_default = True

    def __init__(self, *args, offset=0, **kwargs):
        """
        Loader backend for vmcastle programs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        :param entry_point: start
        """
        super(VMCASTLE, self).__init__(*args,
                arch=arch_from_id("vmcastle"),
                offset=offset,
                entry_point=0,
                base_addr=0,
                **kwargs)
        self.os = "vmcastle"

    @staticmethod
    def is_compatible(stream):
        return True
        # stream.seek(0)
        # stuff = stream.read(0)
        # header = bytes.fromhex(hex()[2:])
        # if stuff == header:
            # log.info(f"matched vmcastle")
            # return True
        # log.info(f"vmcastle NOT matched")
        # return False

register_backend("vmcastle", VMCASTLE)
