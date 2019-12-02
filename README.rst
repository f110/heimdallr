===================
lagrangian-proxy
===================

*Currently under development*

Zero trust proxy for using in corporate.

Deployment
=============

lagrangian-proxy is deployed to a kubernetes by an operator.
You can deploying by yourself. but we highly recommended to using an operator.

Depend on operator
---------------------

* `etcd-operator <https://github.com/coreos/etcd-operator>`_
* `cert-manager <https://github.com/jetstack/cert-manager>`_

Build & Run
=============

First of all, install latest `Bazel <https://bazel.build>`_

Generate some secret keys and certificates for development.

.. code:: console

    $ bazel run //cmd/lpcli -- bootstrap -c $(pwd)/config_debug.yaml

`config_debug.yaml` is configuration for development. DO NOT USE IN PRODUCTION WITHOUT CHANGES.

After generate some secrets and certificates, build and run.

.. code:: console

    $ make run

All dependent libraries are included in the repository.

Reference
============

BeyondCorp by Google.

* `BeyondCorp: A New Approach to Enterprise Security <https://ai.google/research/pubs/pub43231>`_
* `BeyondCorp: Design to Deployment at Google <https://ai.google/research/pubs/pub44860>`_
* `BeyondCorp: The Access Proxy <https://ai.google/research/pubs/pub45728>`_
* `Migrating to BeyondCorp: Maintainig Productivity While Improving Security <https://ai.google/research/pubs/pub46134>`_
* `BeyondCorp: The User Experience <https://ai.google/research/pubs/pub46366>`_
* `BeyondCorp 6: Building a Health Fleet <https://ai.google/research/pubs/pub47356>`_

LICENSE
===========

MIT

Author
=========

Fumihiro Ito <fmhrit@gmail.com>
