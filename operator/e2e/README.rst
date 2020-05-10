=====
e2e
=====

This package provides the e2e testing for controller.

How to run
==============

This package uses ginkgo for BDD framework.

You can run the e2e testing with below.

.. code:: console

    $ go test ./ -crd $(pwd)/../config/crd/bases
