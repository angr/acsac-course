
from angr import Analysis, register_analysis

from .policy_manager import PolicyManager

class StaticPolice(Analysis):
    """
    An angr analysis that performs policy checks with a given set of policies against the binary program.
    """

    def __init__(self, policies=None):
        """
        Constructor.

        :param iterable policies: A collection of policies to be registered with the policy manager.
        """

        self.policy_manager = PolicyManager(self.project, self.kb)

        if policies is not None:
            for policy in policies:
                self.policy_manager.register_policy(policy, policy.name)

    def check(self, functions=None):
        """
        Enforce the policy.

        :param iterable functions: A collection of functions to enforce all policies.
        :return: True if all policies are enforced, False otherwise
        :rtype: bool
        """

        if functions is None:
            functions = self.policy_manager.fast_cfg.functions.values()

        for function in functions:
            self.policy_manager.check_function(function)

register_analysis(StaticPolice, 'StaticPolice')
