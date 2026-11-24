#!/bin/bash
cd ~/haven-deploy/src || exit 1
{
echo "== start $(date -u +%T) load=$(cut -d' ' -f1 /proc/loadavg)"
sudo -n docker build -q -f Dockerfile.idp -t haven-idp:e2e . && echo "idp image built $(date -u +%T)"
sudo -n docker build -q -f Dockerfile.controller -t haven-controller:e2e . && echo "controller image built $(date -u +%T)"
sudo -n docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -E "haven-" 
echo "== import into k3s containerd"
sudo -n docker save haven-idp:e2e haven-controller:e2e | sudo -n k3s ctr -n k8s.io images import - 2>&1 | tail -4
# Pin: this host is above the kubelet image-GC disk threshold, which deletes unused images
# (it removed our freshly imported ones before the pods started).
for i in haven-idp haven-controller; do sudo -n k3s ctr -n k8s.io images label docker.io/library/$i:e2e io.cri-containerd.pinned=pinned >/dev/null 2>&1; done
sudo -n k3s ctr -n k8s.io images ls | grep -E "haven-(idp|controller):e2e" | awk '{print $1, $NF}' 
echo "== done $(date -u +%T)"
} > ~/haven-deploy/build.log 2>&1
