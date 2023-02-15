import io
import argparse
import binascii

from core.signatures import SigsContainer
from core.merge import SignatureMerger

def main():
    parser = argparse.ArgumentParser(usage="%(prog)s --base path --delta path")
    parser.add_argument("--base",  required=True, help="decompressed base signatures file path")
    parser.add_argument("--delta",  required=True, help="decompressed delta signatures file path")

    args = parser.parse_args()

    base_raw_stream  = io.BytesIO(open(args.base, 'rb').read())
    delta_raw_stream = io.BytesIO(open(args.delta, 'rb').read())

    base  = SigsContainer(base_raw_stream)
    delta = SigsContainer(delta_raw_stream)
    delta.parse()

    for sig in delta.signatures:
        if sig.type == 0x73:
            blob = sig.data
            break
    
    blob.parse()
    merger = SignatureMerger(base, blob)
    merged_container = merger.do_merge()

    print(hex(merged_container.crc32))
    
if __name__ == "__main__":
    main()