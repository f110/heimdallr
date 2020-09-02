=====
e2e
=====

This package provides the e2e testing for controller.

How to run
==============

This package uses GoConvey for BDD framework.

You can run the e2e testing with below.

.. code:: console

    $ bazel run //operator/e2e/test:test_test -- -test.v -crd $(pwd)/operator/config/crd

This command is same as ``go test`` .

Or

.. code:: console

    $ bazel build //operator/e2e/test:test_test
    $ ./bazel-bin/operator/e2e/test/test_test_/test_test -test.v -crd $(pwd)/operator/config/crd

If you want colorful output, you build a test binary and run it.

Dependencies
================

* kind