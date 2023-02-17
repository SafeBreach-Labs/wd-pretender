import io
import argparse
import binascii

from core.signatures import Signatures, Delta
from core.rmdx import RmdxBuilder
from core.merge import SignatureMerger
from core.utils import compute_crc32

def main():
    parser = argparse.ArgumentParser(usage="%(prog)s --base path --delta path")
    parser.add_argument("--base",  required=True, help="decompressed base signatures file path")
    parser.add_argument("--delta",  required=True, help="decompressed delta signatures file path")

    args = parser.parse_args()

    base_raw_stream  = io.BytesIO(open(args.base, 'rb').read())
    delta_raw_stream = io.BytesIO(open(args.delta, 'rb').read())

    base  = Signatures(base_raw_stream)
    delta = Delta(delta_raw_stream)
    dblob = delta.do_extract_blob()

    merger = SignatureMerger(base, dblob)
    merged_signatures = merger.do_merge()

    dblob.mrgsize = merged_signatures.length
    dblob.mrgcrc = compute_crc32(merged_signatures.stream)

    dbuilder = RmdxBuilder(delta)


if __name__ == "__main__":
    main()