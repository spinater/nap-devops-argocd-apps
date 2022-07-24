#!/bin/bash

# We need these commands becuase ArgoCD does not support the declarative way this time.

kubectl label ns prometheus-soc --overwrite platform-monitoring=true
