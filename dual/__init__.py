

class IAction:
    def __init__(self, pair):
        self.pair = pair

    def run(self):
        raise NotImplementedError