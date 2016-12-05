
class BaseReturnValue(object):
    """
    Base class for return value classes.
    """
    def __init__(self):
        pass

    def __repr__(self):
        s = "<BaseReturnValue>"
        return s


class ConstantReturnValue(BaseReturnValue):
    """
    Constant return values.
    """
    def __init__(self, value):

        super(ConstantReturnValue, self).__init__()

        self.value = value

    def __repr__(self):
        s = "<ConstantReturnValue, %d>" % (self.value)
        return s


class UnknownReturnValue(BaseReturnValue):
    """
    Unknown (non-constant) return values.
    """
    def __init__(self):
        super(UnknownReturnValue, self).__init__()

    def __repr__(self):
        s = "<UnknownReturnValue>"
        return s
