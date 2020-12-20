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