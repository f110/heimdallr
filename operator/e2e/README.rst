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

The scenarios for the failures (e.g. restoring the datastore) are in ``//operator/e2e/test:fault_test``.
They are not executed by ``--config e2e`` because they take a long time.
If you want to execute them together, you can use ``--config e2e-fault``.

.. code:: console

    $ bazel test --config e2e-fault //operator/e2e/...

If you want to preserve the cluster for debugging, you can use the following command.

.. code:: console

    $ bazel test --config e2e --test_arg="-retain" //operator/e2e/test:test_test

Dependencies
================

* kind