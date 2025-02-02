
#!/bin/bash

set -u -ex



CNI_BIN_DIR=${CNI_BIN_DIR:-"/host/opt/cni/bin/"}
CNI_CONF_DIR=${CNI_CONF_DIR:-"/host/etc/cni/net.d"}
CLAUDE_IPAM_CONFIG=${CLAUDE_KUBECONFIG_FILE_HOST:-"/host/etc/cni/net.d/claude/ipam.yaml"}

# Make a claude.d directory (for our kubeconfig)

mkdir -p $CNI_CONF_DIR/claude


function log()
{
    echo "$(date --iso-8601=seconds) ${1}"
}

function error()
{
    log "ERR:  {$1}"
}

function warn()
{
    log "WARN: {$1}"
}


# copy CLAUDE to the cni bin dir
cp -f /claude/claude $CNI_BIN_DIR

if [ ! -f $CLAUDE_IPAM_CONFIG ]; then
    echo "claude node yaml on the host" $CLAUDE_IPAM_CONFIG
    cp -f /claude-node-config/claude-node.yaml $CLAUDE_IPAM_CONFIG
fi

# ---------------------- end Generate a "kube-config".

# Unless told otherwise, sleep forever.
# This prevents Kubernetes from restarting the pod repeatedly.
should_sleep=${SLEEP:-"true"}
echo "Done configuring CNI.  Sleep=$should_sleep"
/claude/ipam-discovery || echo "ipam discovery failed, skipped."
while [ "$should_sleep" == "true"  ]; do
    /claude/ipam-discovery || echo "ipam discover failed, will retry!"
    sleep 10
done
