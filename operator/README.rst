========================
heimdallr operator
========================

heimdallr operator is the controller for heimdallr proxy.

This operator intends to deploy heimdallr proxy on k8s.

How to development
=====================

#. Create the cluster for development. ``make create-cluster``
#. Write code
#. Run the operator under kind. ``bazel run //operator:run``
#. Print the logs if you needed. ``bazel run //operator:log``

How to update the private key and the certificate for webhook
===============================================================

If the certificate must be update due to expiration, We can make new private key and certificate by ``heimctl``.

.. code:: shell

    $ rm -f operator/webhook.crt operator/webhook.key
    $ bazel run //cmd/heimctl -- util webhook-cert --common-name webhook.heimdallr.svc --private-key $(pwd)/operator/webhook.key --certificate $(pwd)/operator/webhook.crt

Also update the Secret in ``operator/config/manager/manager.yaml`` and caBundle of the ValidatingWebhookConfiguration in ``operator/config/webhook/manifests.yaml``.
