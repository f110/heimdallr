======
e2e
======

This package provides e2e test suite for heimdallr proxy.

How to run
==============

E2E test suite is going to start proxy process internally.

.. code:: console

    $ bazel test //e2e/scenario/...

If you want to show verbose log, then you can pass ``-test.v`` and ``-e2e.verbose`` argument like below.

.. code:: console

    $ bazel test //e2e/scenario:scenario_test --test_arg="-test.v" --test_output=streamed --test_arg="-e2e.verbose"

Show all test cases
---------------------

E2E test suite can show all test case without executing.

.. code:: console

    $ bazel run //e2e/scenario:scenario_test -- -e2e.format doc

Show verbose log
------------------

If ``e2e.verbose`` is true, then it will output the log of the proxy to stdout.

.. code:: console

  $ bazel test //e2e/scenario:scenario_test --test_arg=-e2e.verbose
