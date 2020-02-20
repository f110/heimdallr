===================
lagrangian-proxy
===================

**Currently under development**

Zero trust proxy for using in corporate.

Deployment
=============

lagrangian-proxy is deployed to a kubernetes by the operator.
You can deploying by yourself. but we highly recommend to using the operator.

Depend on
---------------------

* `etcd-operator <https://github.com/coreos/etcd-operator>`_
* `cert-manager <https://github.com/jetstack/cert-manager>`_

When start up the operator, check to exist some CRDs.
If not found all CRDs then the operator not start.

Optional
++++++++++

* `prometheus-operator <https://github.com/coreos/prometheus-operator>`_
* `etcd-backup-operator <https://github.com/coreos/etcd-operator/blob/master/doc/design/backup_operator.md>`_

Build & Run
=============

First of all, install latest `Bazel <https://bazel.build>`_

Generate some secret keys and certificates for development.

.. code:: console

    $ bazel run //cmd/lagctl -- bootstrap -c $(pwd)/config_debug.yaml

`config_debug.yaml` is configuration for development. *8DO NOT USE THIS FILE IN PRODUCTION WITHOUT CHANGES.**

And you need to create a credential file that is Client Secret.
How to get a client secret is depend on an IdP.

After running bootstrap command, build and run.

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
