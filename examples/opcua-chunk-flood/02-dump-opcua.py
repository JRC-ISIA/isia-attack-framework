import asyncio
from asyncua import Client, ua
import re
from pathlib import Path

INPUT_FILE = "results/opcua_active.txt"
PORT = 4840

async def browse_node(node, fh, indent=0):
    """Recursively browse a node and dump name -> value pairs to file handle."""
    try:
        name = await node.read_display_name()
        try:
            val = await node.read_value()
        except ua.UaStatusCodeError:
            val = "<not readable>"
        except Exception:
            val = "<error>"

        fh.write("  " * indent + f"{name.Text}: {val}\n")
    except Exception as e:
        print(e)
        return

    try:
        children = await node.get_children()
        for child in children:
            await browse_node(child, fh, indent + 1)
    except Exception:
        pass

def build_file_name(url):
    filename = url.replace("opc.tcp://", "")
    filename = re.sub(r'[^0-9a-zA-Z]+', '_', filename)
    script_dir = Path(__file__).resolve().parent
    return f"{script_dir}/results/opcua_dump_{filename}.txt"

async def check_host(ip):
    url = f"opc.tcp://{ip}:4840"
    filename = build_file_name(url)
    try:
        async with Client(url) as client:
            root = client.get_root_node()
            with open(filename, "w", encoding="utf-8") as fh:
                fh.write(ip+"\n")
                await browse_node(root, fh)
    except asyncio.TimeoutError as e:
        print(e)
        pass
    except Exception as e:
        print(e)
        pass

async def main():
    script_dir = Path(__file__).resolve().parent
    input_file = f"{script_dir}/results/opcua_active.txt"

    with open(input_file) as f:
        hosts = [line.strip() for line in f if line.strip()]

    for ip in hosts:
        print(f"Check {ip}, dump nodes")
        await check_host(ip)


if __name__ == "__main__":
    asyncio.run(main())