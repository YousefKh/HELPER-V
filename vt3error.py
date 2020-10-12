class VirusTotalAPIError(Exception):
    def __init__(self, massage, err_code):
        super().__init__(massage)
        self.err_code = err_code
