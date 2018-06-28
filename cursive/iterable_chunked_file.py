# module for chunking up a file and iterating over the subsequent pieces

class IterableChunkedFile(object):
    """File object chunk iterator using yield.

    Represents a local file as an iterable object by splitting the file
    into chunks. Avoids the file from being completely loaded into memory.
    """

    def __init__(self, file_object, chunk_size=1024 * 1024 * 128, close=False):
        self.close_after_read = close
        self.file_object = file_object
        self.chunk_size = chunk_size

    def __iter__(self):
        try:
            while True:
                data = self.file_object.read(self.chunk_size)
                if not data:
                    break
                yield data
        finally:
            if self.close_after_read:
                self.file_object.close()

    def __len__(self):
        return len(self.file_object)
