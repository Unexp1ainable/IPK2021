
class ExceptionWithMessage(Exception):
    def __init__(self, message = "") -> None:
        self.message = message
        
class BadRequestException(ExceptionWithMessage):
    pass

class NotFoundException(ExceptionWithMessage):
    pass

class ServerErrorException(ExceptionWithMessage):
    pass
class NotRecognizedException(ExceptionWithMessage):
    pass

class InvalidFormatException(Exception):
    pass

class MissingCRLFException(Exception):
    pass

class InvalidHeaderException(Exception):
    pass

class InvalidProtocolException(Exception):
    pass

