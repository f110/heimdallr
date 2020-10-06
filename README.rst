===================
heimdallr
===================

`[日本語] <./README.ja.rst>`_

**Currently under development**

Zero trust proxy for using in corporate.

Features
===========

* Reverse proxy with identity-aware
* Can proxy the traffic not only HTTP but also SSH or something like
* Beyond NAT on each side of the proxy
* Manage an user by Browser
* Managing an user authority by RBAC
* Easy to deploy to Kubernetes

Configuration
=================

The configuration files divide two parts.

The first part is for the daemon. The second part is for RBAC.

For Daemon
------------

You can control a behavior of the proxy.

Upstream
++++++++++

`Sample file of the configuration of the upstream <./proxies.yaml>`_

RBAC
-----

You will define the role and the permission of RPC.

The role is a set of the upstream and ACL. The permission of RPC is a set of ACL.

Deployment
=============

heimdallr is designed to deploying to a kubernetes by the operator.
You also can deploying by yourself. but we highly recommend to using the operator.

Depend on
---------------------

* `cert-manager <https://github.com/jetstack/cert-manager>`_

When start up the operator, check to exist some CRDs.
If not found all CRDs then the operator not start.

Optional
++++++++++

* `prometheus-operator <https://github.com/coreos/prometheus-operator>`_

How to deploy on k8s
=======================

This section describes how to deploy on k8s.

We've designed this software to deploy to k8s.
Deploying to baremetal, VM or something like that is more complexity than deploying to k8s by the operator.

We've highly recommend to deploying to k8s by the operator.

#. Deploy cert-manager
#. Deploy the operator
#. Create Secret resource which contains the client secret
#. Create Proxy resource

Deploy cert-manager
-----------------------

You're following `official guide <https://cert-manager.io/docs/installation/kubernetes/>`_ .

Deploy the operator
----------------------

We provide the manifest for the operator.

.. code:: shell

    $ kubectl create namespace heimdallr
    $ kubectl apply -f https://github.com/f110/heimdallr/releases/download/v0.9.0/all-in-one.yaml

Create Secret resource
-------------------------

You have to create Secret which contains the client secret before create Proxy resource.

.. code:: shell

    $ kubectl -n heimdallr create secret generic client-secret --from-file=client-secret

Create Proxy resource
-----------------------

The operator automatically creates a related resources after you create Proxy resource.

.. code:: yaml

    apiVersion: proxy.f110.dev/v1
    kind: Proxy
    metadata:
      name: test
      namespace: heimdallr
    spec:
      replicas: 3
      version: v0.9.0
      domain: x.f110.dev
      port: 443
      backendSelector:
        matchLabels:
          instance: test
      roleSelector:
        matchLabels:
          instance: test
      issuerRef:
        name: lets-encrypt
        kind: ClusterIssuer
      identityProvider:
        provider: google
        clientId: [your oauth client id]
        clientSecretRef:
          name: client-secret
          key: client_secret
        redirectUrl: [The callback url you configured]
      rootUsers:
        - [Your email address]
      session:
        type: secure_cookie
        keySecretRef:
          name: cookie-secret

Ingress support
-------------------

The operator also supports Ingress and IngressClass. But very limited support yet.

The operator will not create IngressClass automatically.
If you want to integrate with Ingress, you have to create IngressClass by hand.

.. code:: console

    apiVersion: networking.k8s.io/v1
    kind: IngressClass
    metadata:
      name: heimdallr
      labels:
        instance: proxy-sample
    spec:
      controller: heimdallr.f110.dev/ingress-controller

``.spec.controller`` is constant value. Only accepts ``heimdallr.f110.dev/ingress-controller``.

And ``.metadata.labels`` is a mandatory value. Because it will be inherited to ``Backend``.

Build & Run
=============

First of all, install latest `Bazel <https://bazel.build>`_

Generate some secret keys and certificates for development.

.. code:: console

    $ bazel run //cmd/heimctl -- bootstrap -c $(pwd)/config_debug.yaml

`config_debug.yaml` is configuration for development. **DO NOT USE THIS FILE IN PRODUCTION WITHOUT CHANGES.**

And you need to create a credential file that is Client Secret.
How to get a client secret is depend on an IdP.

After running bootstrap command, build and run.

.. code:: console

    $ make run

All dependent libraries are included in the repository.

Agent
========

The agent is a sidecar of upstream server which behinds NAT.

Traffic can be proxied through the agent even if it cannot be connect to the upstream server due to NAT.

How to run
----------------

The agent is a client program that beside a backend like a sidecar.
the agent will connect to the proxy and relay ingress traffic of proxy.
Thus it can be proxying to the backend that likes behind NAT.

The agent is desgined to run the same host with the backend.
And the agent is also designed for 1:1 corresponding between the agent and the server.

#. Decide the backend's name with your proxy admin
#. Generate CSR(Certificate Signing Request) and private key by heim-agent
#. Send CSR to the proxy admin
#. You got signed certificate from the proxy admin
#. Run heim-agent with signed certificate

DO NOT move the private key to outside of the agent server for any reason.

Generate CSR
+++++++++++++++++

Generating CSR by heim-agent.
CSR includes the backend's name. so you have to pass it by an argument.

.. code:: console

    $ heim-agent --name test --privatekey $HOME/.heimdallr/privatekey.pem

heim-agent will create a CSR in temporary directory.

Start heim-agent with signed certificate
+++++++++++++++++++++++++++++++++++++++++++++

.. code:: console

    $ heim-agent --host your.proxy.f110.dev \
        --name test \
        --privatekey $HOME/.heimdallr/privatekey.pem \
        --backend 127.0.0.1:22 \
        --certificate $HOME/.heimdallr/cert.pem \
        --ca-cert $HOME/.heimdallr/cacert.pem

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
