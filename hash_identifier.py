import hashlib
import argparse
from rich.table import Table
from rich.console import Console
from pathlib import Path
import sys
import json

console = Console()

def calculate_hashes(path):
    #calcolate the hashes for the file
    with open(path, 'rb') as f:
        digestSha256 = hashlib.file_digest(f, "sha256")
        f.seek(0)
        digestSha1 = hashlib.file_digest(f, "sha1")
        f.seek(0)
        digestMD5 = hashlib.file_digest(f, "md5")
    return {
        "path": str(path),
        "sha256": digestSha256.hexdigest(),
        "sha1": digestSha1.hexdigest(),
        "md5": digestMD5.hexdigest()
    }

def collect_results(path, recursion):
    results = []

    if path.is_file():
        results.append(calculate_hashes(path))
    elif path.is_dir():
        for child in path.iterdir():
            if child.is_file():
                results.append(calculate_hashes(child))
            elif child.is_dir():
                if recursion:
                    results.append(collect_results(child, False))
    return results

def print_table(results):
    for r in results:
        table = Table(title=r["path"])
        table.add_column('hash algorithms')
        table.add_column('digest', style="green")
        table.add_row('Sha256', r["sha256"])
        table.add_row('Sha1', r["sha1"])
        table.add_row('MD5', r["md5"])
        console.print(table)

def print_json(results, output_file=None):
    output = json.dumps(results, indent=2)
    if output_file:
        Path(output_file).write_text(output)
        console.print(f"[green]Risultati salvati in {output_file}[/green]")
    else:
        print(output)

#----------------parse the argument----------------#
parser = argparse.ArgumentParser()
parser.add_argument('filePath', type=str)
parser.add_argument('--json', action='store_true', help="Output in a json file")
parser.add_argument('--output', type=str, help="File to write the JSON (require --json)")
parser.add_argument('-s', action='store_false', help="analyze the single directory without recursion")
args = parser.parse_args()
path = Path(args.filePath)


#-------------check if the file exist--------------#

if not path.exists():
    console.print("[red] The directory or the file doesn't exist")
    sys.exit(1)

#--------------calculate the hashes----------------#

results = collect_results(path, args.s)

#------------------how to print--------------------#

if args.json:
    print_json(results, args.output)
else:
    print_table(results)