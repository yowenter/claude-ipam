# Claude: A Simple Etcd Backend CNI IPAM

Just another simple CNI IPAM! 

You can use it as macvlan, bridge .. cni ipam backend.
I've tried [whereabouts](https://github.com/k8snetworkplumbingwg/whereabouts) before, it’s easy to use but there are more bugs and performance issues, such as IP conflict. 

The whereabouts ipam has several bad design patterns:

1 use a large configmap maintaining ip assign records, which doesn’t work good in large network. 

2 use daemonset instance for leader election, and iterate for the whole ip ranges to allocate just one ip. which may lead to ip conflict  in a high concurrent case.

IP conflict is unacceptable! So I write my own!


## Features

### 1 Node Network Management
You can manually setup network for each node or just specify a  `/16` pod cidr, it will slice subnet for each node.


### 2 NO IP Conflict Bug

Since we maintain the IP state machine, there will be no ip conflict bug.


### 3 Works good with Multus CNI

Best pracetice is `Multus CNI + Macvlan|Bridge + Claude IPAM`



## Build

```
export DOCKER_IMAGE=<your own registry>/claude-cni
make docker-build
make docker-push

```

## Deploy

```
# dependency: you should deploy your own etcd 
# and modify the claude-config cm

cd deploy/base
kustomize build | kubectl apply -f -

```









