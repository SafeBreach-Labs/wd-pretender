import io
import argparse
import binascii

from core.signatures import DeltaBlob
from core.merge import SignatureMerger
from core.utils import compute_crc32
from core.vdm import VDM, DeltaVdm, BaseVdm

def main():
    parser = argparse.ArgumentParser(usage="%(prog)s --base path --delta path")
    parser.add_argument("--base",  required=True, help="base vdm file path")
    parser.add_argument("--delta",  required=True, help="delta vdm file path")
    args = parser.parse_args()
    
    basevdm = BaseVdm(args.base)
    deltavdm = DeltaVdm(args.delta)
    
    merged_signatures = SignatureMerger.do_merge(basevdm, deltavdm)

    delta_blob = deltavdm.signatures.find(DeltaBlob.Type)
    delta_blob.mrgsize = merged_signatures.length
    delta_blob.mrgcrc = compute_crc32(merged_signatures.stream)

    print(hex(delta_blob.mrgcrc))

    # change deltavdm to do: base signatures -> pached base signatures
    merged_signatures.parse()
    for signature in merged_signatures.threats:
        print(signature)

    #deltavdm.save(r"C:\Users\omeratt\work\random\valid\")
    

if __name__ == "__main__":
    main()