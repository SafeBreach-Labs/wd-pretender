from core.signatures.deltablob import Blob
from core.signatures.lua import LUAStandAlone
from core.signatures.threat import ThreatBegin, ThreatEnd

SIG_TYPES = {
    0x5c: ThreatBegin,
    0x5d: ThreatEnd,
    0x73: Blob,
    0xbd: LUAStandAlone
}
