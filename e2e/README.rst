======
e2e
======

This package provides e2e test suite for heimdallr proxy.

How to run
==============

E2E test suite is going to start proxy process internally.

.. code:: console

    $ bazel build //cmd/heimdallr-proxy
    $ bazel run //e2e/scenario:scenario_test -- -e2e.binary $(pwd)/bazel-bin/cmd/heimdallr-proxy/heimdallr-proxy_/heimdallr-proxy

If you want to show verbose log, then you can pass ``-test.v`` argument.

Show all test cases
---------------------

E2E test suite can show all test case without executing.

.. code:: console

    $ bazel run //e2e/scenario:scenario_test -- -e2e.format doc