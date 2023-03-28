from dual import IAction
from core.signatures.threat import Threat

class AddThreat(IAction):
    def __init__(self, pair, threat: Threat):
        super().__init__(pair)
        self.threat = threat

    def run(self):
        threat_data = self.threat.pack_bytes()
        self.pair.delta.insert_signature_as_action(threat_data)
        