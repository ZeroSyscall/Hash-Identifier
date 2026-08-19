import hashlib
import argparse
from rich.table import Table
from rich.console import Console
from pathlib import Path
import sys

#parse the argument
parser = argparse.ArgumentParser()
parser.add_argument('filePath', type=str)

path = Path(parser.parse_args().filePath)
console = Console()

def analyze_single_file(path):
    #calcolate the hashes for the file
    with open(path, 'rb') as f:
        digestSha256 = hashlib.file_digest(f, "sha256")
        f.seek(0)
        digestSha1 = hashlib.file_digest(f, "sha1")
        f.seek(0)
        digestMD5 = hashlib.file_digest(f, "md5")

    table = Table(title=str(path))

    table.add_column('hash algorithms')
    table.add_column('digest', style="green")

    table.add_row('Sha256', digestSha256.hexdigest())
    table.add_row('Sha1', digestSha1.hexdigest())
    table.add_row('MD5', digestMD5.hexdigest())

    console.print(table)

def analyze_directory(path):
    for child in path.iterdir(): 
        if child.is_dir():
            analyze_directory(child)
        elif child.is_file():
            analyze_single_file(child)

#-------------check if the file exist-------------#

if not path.exists():
    console.print("[red] The directory or the file doesn't exist")
    sys.exit(1)

#--------check if it's a directory or file--------#
if path.is_file():
    analyze_single_file(path)

if path.is_dir():
    analyze_directory(path)
