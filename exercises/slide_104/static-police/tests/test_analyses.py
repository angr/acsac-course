
# This is a collection of test case on analyses implemented in Flea

import argparse
import os.path

import nose.tools

import angr
import staticpolice


def test_return_value_analysis():
    """
    Smoke test for ReturnValueAnalysis
    """

    p = angr.Project(os.path.join('..', 'test_binaries', 'return_values'), load_options={'auto_load_libs': False})

    cfg = p.analyses.CFGFast()

    f_return0 = cfg.kb.functions.function(name='return_0')
    f_return1 = cfg.kb.functions.function(name='return_1')
    f_return2 = cfg.kb.functions.function(name='return_2')

    nose.tools.assert_is_not_none(f_return0)
    nose.tools.assert_is_not_none(f_return1)
    nose.tools.assert_is_not_none(f_return2)

    for f, return_value in [ (f_return0, 0), (f_return1, 1), (f_return2, 2) ]:
        cfg_accurate = p.analyses.CFGAccurate(
            starts=(f.addr, ),
            call_depth=0,
            keep_state=True,
            base_graph=f.graph
        )
        data_dep = p.analyses.DDG(cfg_accurate)

        rva = p.analyses.ReturnValueAnalysis(f, data_dep)

        nose.tools.assert_equal(len(rva.return_values), 1)
        nose.tools.assert_true(isinstance(rva.return_values[0], staticpolice.analyses.ConstantReturnValue))
        nose.tools.assert_equal(rva.return_values[0].value, return_value)

def test_data_dependency_analysis():

    pass


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
