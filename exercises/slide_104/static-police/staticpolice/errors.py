
class StaticPoliceBaseError(Exception):
    pass

class StaticPoliceBaseNotice(Exception):
    pass

#
# Generic errors
#

class FunctionNotFoundError(StaticPoliceBaseError):
    pass

class StaticPoliceTypeError(StaticPoliceBaseError):
    pass

class StaticPoliceKeyNotFoundError(StaticPoliceBaseError):
    pass

#
# Policy notices
#

class PolicySkipFunctionNotice(StaticPoliceBaseNotice):
    pass
