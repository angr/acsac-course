
import logging

from angr import KnowledgeBase

from ..errors import StaticPoliceTypeError, PolicySkipFunctionNotice
from ..analyses.return_values import ConstantReturnValue
from ..check_result import CheckResult
from .policy_base import PolicyBase

l = logging.getLogger('policies.return_values')


class ReturnValues(PolicyBase):
    """
    Policy ReturnValues specifies a set of all possible return values a function may have, and then checks if the
    function returns any value outside of the pre-defined range.

    Assumptions:
    - Return values are returned in the return value register specified by the normal calling convention of the
      architecture.
    - Return values are determined only by the current function, which is to say, if the return value of function A
      comes from the call to function B, this policy cannot properly check that.
    """

    def __init__(self, name=None, return_values=None, function_address=None, project=None, manager=None):
        """
        Constructor.

        :param str name: Name of the policy.
        :param iterable return_values: A collection of allowed return values from this function.
        :param int function_address: The address of the function to check.
        """

        # sanity checks
        if not return_values:
            raise StaticPoliceTypeError('"return_values" must be specified.')
        if function_address is None:
            raise StaticPoliceTypeError('"function_address" must be specified.')

        name = "ReturnValueChecker" if not name else name

        super(ReturnValues, self).__init__(name, project=project, manager=manager)

        self.return_values = return_values
        self.function_address = function_address

    def function_check(self, function):
        """
        Check if the specific function returns any value outside of the predefined scope.

        :param angr.knowledge.Function function: The function to check.
        :return: True if the policy is respected, False otherwise.
        :rtype: bool
        """

        if function.addr != self.function_address:
            # skip this function
            raise PolicySkipFunctionNotice()

        # the temporary knowledge base
        tmp_kb = KnowledgeBase(self.project, self.project.loader.main_bin)

        cfg = self.project.analyses.CFGAccurate(
            starts=(function.addr,),
            keep_state=True,
            call_depth=0,
            kb=tmp_kb,
        )

        # generate the data dependence graph on the function
        dep_graph = self.project.analyses.DataDependencyAnalysis(
            cfg,
            kb=tmp_kb
        )

        # perform a return value analysis
        ret_val = self.project.analyses.ReturnValueAnalysis(function, dep_graph)

        result = True

        # check the return values
        for r in ret_val.return_values:  # type: ConstantReturnValue
            if r.value not in self.return_values:
                l.warning('Policy violation: return value %s not found in predefined set of return values specified by '
                          'the policy.', r.value)
                cr = CheckResult(self, False, function=function, unexpected_value=r.value)
                self._add_result(cr)
                result = False

                if self._failfast:
                    return result

        if result is True:
            cr = CheckResult(self, True, function=function)
            self._add_result(cr)

        return True
