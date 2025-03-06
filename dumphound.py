#!/usr/bin/env python3
from sockcreator import sock_table
import asyncio
import os
import sys
from collections import deque, defaultdict
from typing import Deque, Tuple, Dict
from dataclasses import dataclass

# Constants
DUMP_FILE = "/tmp/hound_dump"
BUFFER_SIZE = 65536
OUTPUT_INTERVAL_SEC = 5

@dataclass
class Config:
    """Configuration settings."""
    interface: str = 'any'
    resolve_mode: bool = False
    verbose_mode: bool = False
    resolve_names: bool = False

async def setup_tcpdump(config: Config) -> asyncio.subprocess.Process:
    os.system(f'sudo rm -f {DUMP_FILE}; sudo touch {DUMP_FILE}; sudo chmod 666 {DUMP_FILE}')
    cmd = (
        f"sudo tcpdump -i {config.interface} "
        f"not arp and not host 127.0.0.1 and "
        f"not host 172.17.0.1 and not host 172.17.0.6 and "
        f"not host ::1 -qlnn > {DUMP_FILE}"
    )
    return await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

async def read_dump_file(queue: Deque[str]):
    position = 0
    while True:
        try:
            with open(DUMP_FILE, 'rb') as f:
                f.seek(position)
                chunk = f.read(BUFFER_SIZE)
                if chunk:
                    text = chunk.decode('utf-8', errors='ignore')
                    lines = text.splitlines()
                    for line in lines:
                        queue.append(line)
                    position = f.tell()
                await asyncio.sleep(0.01)
        except FileNotFoundError:
            await asyncio.sleep(0.1)
            continue
        except Exception as e:
            print(f"Error reading dump file: {e}")
            await asyncio.sleep(0.1)



def humanbytes(B):
    """Return the given bytes as a human friendly KB, MB, GB, or TB string with color coding"""
    B = float(B)
    KB = float(1024)
    MB = float(KB ** 2)
    GB = float(KB ** 3)
    TB = float(KB ** 4)

    # ANSI color codes
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

    # Determine color based on size
    if B >= GB:
        color = RED
    elif B >= 100 * MB:
        color = YELLOW
    elif B >= MB:
        color = GREEN
    else:
        color = BLUE

    # Format the size
    if B < KB:
        formatted = '{0} {1}'.format(B, 'Bytes' if 0 == B > 1 else 'Byte')
    elif KB <= B < MB:
        formatted = '{0:.2f} KB'.format(B/KB)
    elif MB <= B < GB:
        formatted = '{0:.2f} MB'.format(B/MB)
    elif GB <= B < TB:
        formatted = '{0:.2f} GB'.format(B/GB)
    elif TB <= B:
        formatted = '{0:.2f} TB'.format(B/TB)

    return f"{color}{formatted:>10}{ENDC}"

def opt_parse_rawip(rawip):
    """
    Parses tcpdump output line using precise delimiters.
    """
    try:
        if 'IP ' not in rawip:
            return None
        ip_part = rawip.split('IP ')[1]
        src, remainder = ip_part.split(' > ')
        dst, proto_length = remainder.split(': ')
        src_ip, src_port = src.rsplit('.', 1)
        dst_ip, dst_port = dst.rsplit('.', 1)
        length = int(proto_length.split()[-1])
        return {
            "SRC": src_ip,
            "s_port": src_port,
            "DST": dst_ip,
            "d_port": dst_port,
            "Length": length
        }
    except Exception as e:
        print(f"Parsing error: {e} on line: {rawip}")
        return None

async def process_queue(queue: Deque[str], output_data: Dict[Tuple[str, str, str, str], Tuple[int, int]]):
    while True:
        if queue:
            line = queue.popleft()
            data = opt_parse_rawip(line)
            if data is not None:
                key = (data["SRC"], data["s_port"], data["DST"], data["d_port"])
                if key in output_data:
                    total_bytes, count = output_data[key][:2]
                    output_data[key] = (total_bytes + data["Length"], count + 1) + output_data[key][2:]
                else:
                    output_data[key] = (data["Length"], 1, "~", "~", "~", "~")
        else:
            await asyncio.sleep(0.01)

def update_with_sock_info(output_data: Dict[Tuple[str, str, str, str], Tuple[int, int]]):
    """
    Updates the main dictionary with fields from sock_table if matches are found,
    checking both directions (src->dst and dst->src).
    """
    sock_infos = sock_table()
    sock_dict = {
        (info['source'], str(info['s_port']), info['dest'], str(info['d_port'])): (
            info['proc'], info['pid'], info['fd'], info['proto']
        )
        for info in sock_infos
    }
    reverse_sock_dict = {
        (info['dest'], str(info['d_port']), info['source'], str(info['s_port'])): (
            info['proc'], info['pid'], info['fd'], info['proto']
        )
        for info in sock_infos
    }

    for key, value in output_data.items():
        matched_info = sock_dict.get(key) or reverse_sock_dict.get(key)
        if matched_info:
            output_data[key] = value[:2] + matched_info

async def output_report(output_data: Dict[Tuple[str, str, str, str], Tuple[int, int]]):
    DISPLAY_LIMIT = 19
    TAIL_LINES = 3

    while True:
        await asyncio.sleep(OUTPUT_INTERVAL_SEC)
        if output_data:
            update_with_sock_info(output_data)  # Update with sock_table before reporting
            sorted_data = sorted(output_data.items(), key=lambda item: item[1][0], reverse=True)
            total_lines = len(sorted_data)
            print("\nActive Network Sockets (sorted by total bytes):")
            if total_lines <= DISPLAY_LIMIT:
                for entry in sorted_data:
                    print_formatted_entry(entry)
            else:
                for i in range(DISPLAY_LIMIT - TAIL_LINES):
                    print_formatted_entry(sorted_data[i])
                print("----~~~----~~~ truncated ----~~~----~~~")
                for i in range(-TAIL_LINES, 0, 1):
                    print_formatted_entry(sorted_data[i])
            print('--- End of Report ---\n')



# New Section
def print_formatted_entry(entry):
    """Utility function for printing entries with formatted output."""
    (src_ip, src_port, dst_ip, dst_port), (total_bytes, count, *extra) = entry
    proc, pid, fd, proto = extra if len(extra) == 4 else ("~", "~", "~", "~")
    
    # Format bytes with color and human readable format
    bytes_formatted = humanbytes(total_bytes)
    
    if '-fd' in sys.argv:
        print(
            f"Src: {src_ip:>15}:{src_port:<5} -> "
            f"Dst: {dst_ip:>15}:{dst_port:<5} "
            f"Bytes: {bytes_formatted} "
            f"Count: {count:>6} "
            f"Proc: {proc:<15} "
            f"pid: {pid:<6} "
            f"FD: {fd:<4} "
            f"Proto: {proto:<4}"
        )
    else:
        print(
            f"Src: {src_ip:>15}:{src_port:<5} -> "
            f"Dst: {dst_ip:>15}:{dst_port:<5} "
            f"Bytes: {bytes_formatted} "
            f"Count: {count:>6} "
            f"Proc: {proc:<15}"
        )
def parse_args() -> Config:
    config = Config()
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '-R':
            config.resolve_mode = True
        elif arg.lower() in ('-i', '-I'):
            if i + 1 < len(sys.argv):
                config.interface = sys.argv[i + 1]
                i += 1
            else:
                print("Error: Interface name must be specified after -i/-I")
                sys.exit(1)
        i += 1
    return config

async def main():
    config = parse_args()
    queue: Deque[str] = deque()
    output_data: Dict[Tuple[str, str, str, str], Tuple[int, int]] = defaultdict(
        lambda: (0, 0, "~", "~", "~", "~")
    )
    tcpdump_process = await setup_tcpdump(config)
    try:
        reader = asyncio.create_task(read_dump_file(queue))
        processor = asyncio.create_task(process_queue(queue, output_data))
        reporter = asyncio.create_task(output_report(output_data))
        await asyncio.gather(reader, processor, reporter)
    except asyncio.CancelledError:
        print("\nShutting down...")
    finally:
        tcpdump_process.terminate()
        await tcpdump_process.wait()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram terminated by user")
