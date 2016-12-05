
import logging

import angr

l = logging.getLogger('policies.policy_base')


class PolicyBase(object):
    """
    This class acts as the base class of any policy.

    :ivar str name: Name of the policy.
    :ivar angr.Project project: The associated angr project instance. Registered using _register_project() method.
    :ivar angr.KnowledgeBase kb: The associated angr knowledgebase instance. Registered using _register_project() method.
    """

    def __init__(self, name, project=None, manager=None):
        """
        Constructor.

        :param str name: Name of this policy
        :param angr.Project project: The associated angr project.
        :param PolicyManager manager: The associated policy manager instance.
        """
        self.name = name

        self.project = project  # type: angr.Project
        self.kb = None  # type: angr.knowledgebase.KnowledgeBase
        if project:
            self.kb = project.kb

        self.manager = manager # type: PolicyManager

    #
    # Overriden methods from the base class
    #

    def __repr__(self):
        return "<Policy %s>" % self.name

    #
    # Public interfaces
    #

    def function_check(self, function):
        """
        Check if the policy is violated on a certain function.

        :param function: The function to check the policy against.
        :type function: angr.knowledge.Function or int
        :return: True if the policy is respected, False if the policy is violated.
        :rtype: bool
        """

        raise NotImplementedError()

    def functions_check(self, functions):
        """
        Check if the policy is violated on the given set of functions.

        :param iterable functions: A set of functions to check the policy against.
        :return: True if the policy is respected, False if the policy is violated.
        :rtype: bool
        """

        raise NotImplementedError()

    def program_check(self):
        """
        Check if the policy is violated in the entire program.

        :return: True if the policy is respected, False if the policy is violated.
        :rtype: bool
        """

        raise NotImplementedError()

    #
    # Private interfaces
    #

    def _add_result(self, r):
        if self.manager is not None:
            self.manager.add_result(r)

    @property
    def _failfast(self):
        if self.manager is None:
            return True
        else:
            return self.manager.failfast

    @property
    def _fast_cfg(self):
        if self.manager is not None:
            return self.manager.fast_cfg

        l.warning('Policy %s does not have an associated policy manager. The fast control flow graph is not cached.')
        tmp_kb = angr.KnowledgeBase(self.project, self.project.loader.main_bin)
        return self.project.analyses.CFGFast(kb=tmp_kb)

    #
    # Private methods
    #

    def _register_project(self, project, kb):
        """
        Associate an angr Project with this policy.

        :param angr.Project project: The angr project.
        :param angr.KnowledgeBase kb: The knowledgebase object.
        :return: None
        """

        self.project = project
        self.kb = kb

    def _register_manager(self, manager):
        """
        Associate a policy manager with this policy instance.

        :param PolicyManager manager: The policy manager.
        :return: None
        """

        self.manager = manager
