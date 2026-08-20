import hashlib
import argparse
from rich.table import Table
from rich.console import Console
from pathlib import Path
import sys
import json
import time
import requests
import os
from dotenv import load_dotenv

console = Console()

def calculate_hashes(path):
    #
    chunk_size = 32768

    #calcolate the hashes for the file
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    try:
        with open(path, 'rb') as f:
            # update can upload in the RAM only a chunk of the file at the time, so can process bigger file too
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

        return {
            "path": str(path),
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "md5": md5.hexdigest()
        }
    
    except (PermissionError, OSError) as e:
        console.print(f"[yellow]skipped {path}: {e}[/yellow]")
        return None

def collect_results(path, recursion):
    results = []

    if path.is_file():
        results.append(calculate_hashes(path))
    elif path.is_dir():
        for child in path.iterdir():
            if child.is_symlink():
                continue
            if child.is_file():
                results.append(calculate_hashes(child))
            elif child.is_dir():
                if recursion:
                    results.extend(collect_results(child, recursion))
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
parser.add_argument('-s','--no-recursion', dest='recursion', action='store_false', help="analyze the single directory without recursion")
parser.add_argument('--malware', action='store_true', help="send API request to malware baazar for looking if the file is a known malware")
args = parser.parse_args()
path = Path(args.filePath)


#-------------check if the file exist--------------#

if not path.exists():
    console.print("[red] The directory or the file doesn't exist")
    sys.exit(1)

#--------------calculate the hashes----------------#

results = collect_results(path, args.recursion)

#------------------how to print--------------------#

if args.json:
    print_json(results, args.output)
else:
    print_table(results)

#-----------------check for malware baazar-------------------#

if args.malware:
    API_URL = "https://mb-api.abuse.ch/api/v1/"

    load_dotenv()
    API_KEY = os.environ.get("MY_API_KEY")

    if not API_KEY:
        console.print("[red]MY_API_KEY not configured. Copy .env.example in .env and put your key.[/red]")
        sys.exit(1)

    headers = {"Auth-key": API_KEY}

    for file_data in results:
        hash = file_data["sha256"]
        file_name = file_data["path"]

        data = {
            "query": "get_info",
            "hash": hash
        }

        try:
            response = requests.post(API_URL, data=data, headers=headers)

            if response.status_code == 429:
                #too many request
                time.sleep(60)
                continue

            if response.status_code == 200:
                result = response.json().get('query_status')
                if result == "hash_not_found":
                    console.print(f'info from file [blue]{file_name} : [green]{result}')
                elif result == "ok":
                    console.print(f'info from file [blue]{file_name} : [yellow]{result}')
                else:
                    console.print(f'info from file [blue]{file_name} : [red]{result}')
            else:
                console.print(f'[red] HTTP error {response.status_code}')

        except Exception as error:
            console.print(f"[red]Malware Bazaar request failed: {error}[/red]")

        time.sleep(1)