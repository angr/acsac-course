
from angr import KnowledgeBase

from ..errors import FunctionNotFoundError
from .policy_base import PolicyBase

class StackVariableInitialization(PolicyBase):
    """
    Policy StackVariableInitialization checks all variable locations on the stack, and make sure they are initialized
    before use, i.e. no value consuming before value assignment.

    Since we do not perform any complex variable identification, we only identify simple stack variable locations by
    synthesizing the direct stack variable accesses. For instance,
        mov dword ptr [ebp+8], eax
    implies that there is a stack variable location at ebp+8, and the variable size is 4. To reason about variables
    accessed in loops, a static analysis technique like VSA is essential.
    """

    def __init__(self, name=None):
        """
        Constructor.

        :param str name: Name of the policy.
        """

        name = "ReturnValueChecker" if not name else name

        super(StackVariableInitialization, self).__init__(name)

    #
    # Implementation of public interfaces
    #

    def function_check(self, function):

        if isinstance(function, (int, long)):
            function = self.kb.functions.get(function, None)

        if function is None:
            # the function is not found
            raise FunctionNotFoundError('The function specified is not found. Please make sure the function you '
                                        'specified is correct, and the correct knowledge base with function '
                                        'information is passed in.'
                                        )

        # create a temporary knowledgebase so that the new CFG does not overwrite the existing global CFG
        tmp_kb = KnowledgeBase(self.project, self.kb.obj)

        # create an accurate control flow graph for this function
        cfg = self.project.analyses.CFGAccurate(kb=tmp_kb, base_graph=function)

        import ipdb; ipdb.set_trace()

    #
    # Implementation of private interfaces
    #


