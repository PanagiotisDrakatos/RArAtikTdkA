from pathlib import Path


class FileData(object):
    def __init__(self, path):
        self.filename = Path(path)
        self.filename.touch(exist_ok=True)  # will create file, if it exists will do nothing
        self.file = open(self.filename, "w")

    def write(self, prefix, iterate, data):
        self.file.write("10.0." + prefix + "." + iterate + " " + data + ".com" + "\n")
