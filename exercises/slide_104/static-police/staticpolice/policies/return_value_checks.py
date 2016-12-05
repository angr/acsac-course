
import logging

from simuvex import SimRegisterVariable
import angr
from angr import KnowledgeBase
from angr.analyses.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable

from .policy_base import PolicyBase
from ..analyses.return_values import ReturnValueAnalysis

l = logging.getLogger('policies.return_value_checks')


class ReturnValueChecks(PolicyBase):
    """
    Policy ReturnValueChecks makes sure the return value from a function is checked before using. For example, a call to
    malloc() usually returns a valid pointer, but sometimes a NULL is returned when there the memory pressure of the
    target system is high, and memory allocation fails. Assuming the return value of malloc() always being a valid
    pointer is wrong and unsafe. This policy can be used to find situations where no check exists for the return value
    of functions like malloc().
    """

    def __init__(self, name=None, project=None, manager=None):
        """
        Constructor.

        :param str name: Name of the policy.
        """

        name = "ReturnValueChecks" if not name else name

        super(ReturnValueChecks, self).__init__(name, project=project, manager=manager)

    def function_check(self, function):
        """


        :param angr.knowledge.Function function: The function to be checked against.
        :return: True if the policy is respected, False otherwise.
        :rtype: bool
        """

        if function.returning is False:
            l.warning('Function %#x does not return.', function.addr)
            return True

        # find all places where the function is called

        cfg = self._fast_cfg

        function_node = cfg.get_any_node(function.addr)

        if not function_node:
            # the function is not found
            l.warning('Function %#x is not found in the control flow graph.', function.addr)
            return True

        # find all predecessors, which are callers to this function
        predecessors = cfg.get_all_predecessors(function_node)

        if not predecessors:
            # the function is not called from anywhere, or we cannot resolve the caller
            l.warning('Function %#x is not called by any node throughout the control flow graph.', function.addr)
            return True

        # for each function that the caller is in, generate a data dependency graph
        for pred in predecessors:  # type: angr.analyses.cfg_node.CFGNode
            func_addr = pred.function_address

            if func_addr is None:
                continue

            caller_func = cfg.functions.get(func_addr, None)  # type: angr.knowledge.Function
            if caller_func is None:
                continue

            tmp_kb = KnowledgeBase(self.project, self.project.loader.main_bin)
            caller_func_cfg = self.project.analyses.CFGAccurate(
                call_depth=0,
                base_graph=caller_func.graph,
                keep_state=True,
            )
            dep_graph = self.project.analyses.DataDependencyAnalysis(
                caller_func_cfg,
                kb=tmp_kb,
            )

            # analyze on dep_graph
            ret_val_reg = ReturnValueAnalysis.RETURN_VALUE_REGISTERS[self.project.arch.name]
            ret_val_reg_offset, ret_val_reg_size = self.project.arch.registers[ret_val_reg]
            ret_var = SimRegisterVariable(ret_val_reg_offset, ret_val_reg_size * 8)

            # return site
            return_site_addr = pred.addr + pred.size

            ret_var_def = ProgramVariable(ret_var, CodeLocation(return_site_addr, -1))
            # TODO: add return value nodes in DataDependencyAnalysis

            consumers = dep_graph.find_consumers(ret_var_def)

            if not consumers:
                l.warning('Return value of function %#x is not checked at calling site %#x.', function.addr, pred.addr)
                return False

        return True
