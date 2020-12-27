=====
e2e
=====

This package provides the e2e testing for controller.

How to run
==============

This package uses GoConvey for BDD framework.

You can run the e2e testing with below.

.. code:: console

    $ bazel test --config e2e //operator/e2e/test:test_test

If you want to preserve the cluster for debugging, you can use the following command.

.. code:: console

    $ bazel test --config e2e --test_arg="-retain" //operator/e2e/test:test_test

Dependencies
================

* kind