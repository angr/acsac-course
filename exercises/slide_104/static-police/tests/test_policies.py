
# This is a collection of test cases on policies and policy checking procedures

import argparse
import os.path

import nose.tools

import angr
import staticpolice
from staticpolice.policies import ReturnValues, ReturnValueChecks

def test_return_values():
    """
    Smoke test for policy ReturnValues
    """

    p = angr.Project(os.path.join('..', 'test_binaries', 'return_values'), load_options={'auto_load_libs': False})

    cfg = p.analyses.CFGFast()

    f_return0 = cfg.kb.functions.function(name='return_0')
    f_return1 = cfg.kb.functions.function(name='return_1')
    f_return2 = cfg.kb.functions.function(name='return_2')

    nose.tools.assert_is_not_none(f_return0)
    nose.tools.assert_is_not_none(f_return1)
    nose.tools.assert_is_not_none(f_return2)

    function_and_policies = [
        (f_return0, ReturnValues(return_values=[0], function_address=f_return0.addr, project=p)),
        (f_return1, ReturnValues(return_values=[1], function_address=f_return1.addr, project=p)),
        (f_return2, ReturnValues(return_values=[2], function_address=f_return2.addr, project=p)),
    ]

    for f, policy in function_and_policies:
        # all those policies should succeed
        r = policy.function_check(f)
        nose.tools.assert_true(r)

    # this one is gonna fail
    policy = ReturnValues(return_values=[1], function_address=f_return2.addr, project=p)
    r = policy.function_check(f_return2)
    nose.tools.assert_false(r)

def test_return_value_checks():
    """
    Smoke test for policy ReturnValueChecks
    """

    p = angr.Project(os.path.join('..', 'test_binaries', 'return_value_checks'), load_options={'auto_load_libs': False})

    cfg = p.analyses.CFGFast()

    f_return1 = cfg.kb.functions.function(name='return_1')
    policy_manager = staticpolice.PolicyManager(p, p.kb)

    nose.tools.assert_is_not_none(f_return1)

    function_and_policies = [
        (f_return1, ReturnValueChecks(project=p, manager=policy_manager)),
    ]

    for f, policy in function_and_policies:
        # should succeed
        r = policy.function_check(f)
        nose.tools.assert_true(r)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--test', help='Name of the test to run.')
    args = parser.parse_args()

    if args.test:
        g = globals()
        for k, v in g.iteritems():
            if k == 'test_%s' % args.test:
                v()
                break
        else:
            raise KeyError('Test %s is not found.' % args.test)

    else:

        g = globals()
        for k, v in g.iteritems():
            if k.startswith('test_') and hasattr(v, '__call__'):
                v()

if __name__ == '__main__':
    main()
