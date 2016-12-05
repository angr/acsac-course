
from .errors import StaticPoliceTypeError
from .check_result import CheckResult

class PolicyManager(object):
    """
    A manager of all policies.
    """

    def __init__(self, project, kb, failfast=False):
        """
        Constructor.

        :param angr.Project project: The angr project instance.
        :param angr.KnowledgeBase kb: The knowledgebase associated to all policies.
        :param bool failfast: When set to True, policy checking procedure will be immediately terminated if any policy
                              check fails. Otherwise all policy check failures are recorded.
        """

        self.project = project
        self.kb = kb
        self.failfast = failfast

        self.policies = {}
        self._cfg = None
        self.results = [ ]

    def register_policy(self, policy, name):
        """
        Register a policy with the policy manager.

        :param policies.PolicyBase policy: The policy object to register.
        :return: None
        """

        self.policies[name] = policy

        # associate the policy to the current project
        policy._register_project(self.project, self.kb)
        # associate the policy to the policy manager
        policy._register_manager(self)

    def check_function(self, function):
        """

        :param function:
        :return:
        """

        result = True

        for _, p in self.policies.iteritems():

            if not p.check_function(function):
                result = False
                if self.failfast:
                    return result

        return result

    def check_functions(self, functions):
        """

        :param functions:
        :return:
        """

        result = True

        for _, p in self.policies.iteritems():

            if not p.check_functions(functions):
                result = False
                if self.failfast:
                    return result

        return result

    #
    # Public methods for policies
    #

    def add_result(self, r):
        """
        Append a policy check result.

        :param CheckResult r: The check result to add.
        :return: None
        """

        if not isinstance(r, CheckResult):
            raise StaticPoliceTypeError('add_result() only accepts CheckResult instances.')

        self.results.append(r)

    #
    # Properties
    #

    @property
    def fast_cfg(self):
        """
        Get a fast CFG. Note that it is only generated upon the first time this function is called, and then the CFG is
        cached in self._cfg.

        :return: A full-program control flow graph.
        :rtype: angr.analyses.CFGFast
        """

        if self._cfg is None:
            self._cfg = self.project.analyses.CFGFast()

        return self._cfg
