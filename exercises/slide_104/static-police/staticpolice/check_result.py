
class CheckResult(object):
    """
    Result of a policy check.
    """

    def __init__(self, policy, result, function=None, **kwargs):
        """
        Constructor.

        :param PolicyBase policy: The policy that is checked.
        :param obj result: Result of the policy checking.
        :param angr.knowledge.Function function: The function where this policy is checked against. May not be set (in
                                                 case the policy is not correlated to a single function).
        """

        self.policy = policy
        self.result = result
        self.function = function

        self.info = kwargs.copy()

    def __repr__(self):
        s = "<CheckResult of %s: %s>" % (self.policy.name, self.result)

        return s

from .policies import PolicyBase
