
import logging

from simuvex import SimRegisterVariable, SimConstantVariable
from angr import Analysis, register_analysis
from angr import knowledge
from angr.analyses.ddg import DDG, ProgramVariable

from ...errors import StaticPoliceTypeError, StaticPoliceKeyNotFoundError
from .return_values import ConstantReturnValue, UnknownReturnValue

l = logging.getLogger('return_value_analysis')


class ReturnValueAnalysis(Analysis):
    """
    Try getting all possible return values of this function by analyzing the data dependency graph. Currently it only
    handles constant return values. That is to say, any return value that does not appear to be a constant in
    disassembly is shown as an UnknownReturnValue.

    Return values on each path are resolved individually. For example, function malloc() returns a valid pointer on one
    path, and NULL on some other paths, the analysis result will look like the following:

    return_values = [
        <UnknownReturnValue>  # when it returns a pointer
        <ConstantReturnValue, 0>  # on other paths where a NULL is returned
    ]

    """

    RETURN_VALUE_REGISTERS = {
        'X86': 'eax',
        'AMD64': 'rax'
    }

    def __init__(self, function, data_dep):
        """
        Constructor.

        :param angr.knowledge.Function function: The function to analyze.
        :param DDG data_dep: The data dependency analysis result.
        """

        # sanity check
        if not isinstance(data_dep, DDG):
            raise StaticPoliceTypeError('"data_dep" must be an instance of DDG.')

        if not isinstance(function, knowledge.Function):
            raise StaticPoliceTypeError('"function" must be an instance of angr.knowledge.Function.')

        self._function = function
        self._data_dep = data_dep

        self.return_values = [ ]

        self._analyze()

    def _analyze(self):
        """
        The core analysis method.

        :return: None
        """

        # get the register that stores return value
        return_reg = self.RETURN_VALUE_REGISTERS.get(self.project.arch.name, None)
        if return_reg is None:
            raise StaticPoliceKeyNotFoundError('Return register is not specified for architecture %s.' % self.project.arch.name)

        return_reg_offset, return_reg_size = self.project.arch.registers[return_reg]

        variable = SimRegisterVariable(return_reg_offset, return_reg_size * 8)

        all_defs = self._data_dep.find_definitions(variable)

        # apparently we only care about those final definitions, i.e. definitions that do not have any consumers or
        # killers
        defs = [ ]
        for d in all_defs:  # type: ProgramVariable
            if not self._data_dep.find_consumers(d) and not self._data_dep.find_killers(d):
                defs.append(d)

        if not defs:
            l.warning('Cannot find any definition for return value.')
            return

        return_values = [ ]

        # trace each definition backwards
        for d in defs:
            sources = self._data_dep.find_sources(d)

            if not sources:
                # umm what's going on
                continue

            for s in sources:
                if isinstance(s.variable, SimConstantVariable):
                    return_values.append(ConstantReturnValue(s.variable.value))
                else:
                    return_values.append(UnknownReturnValue())

        self.return_values = return_values

register_analysis(ReturnValueAnalysis, 'ReturnValueAnalysis')
