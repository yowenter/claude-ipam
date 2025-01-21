package leader

import (
	"context"
	"os"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/yowenter/claude-ipam/pkg/types"
	"github.com/yowenter/claude-ipam/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// https://github.com/kubernetes-retired/contrib/pull/353/files

func RunWithLease(ctx context.Context, electOps *types.ElectionOption, runner func(ctx context.Context), cancel func()) error {
	client, err := utils.NewK8sClient(utils.InCluster())
	if err != nil {
		return err
	}

	// set identity key to pod name or random uuid
	identityKey := os.Getenv("HOSTNAME")
	if identityKey == "" {
		identityKey = uuid.NewString()
	}

	log.Infof("Trying to acquire leader lock %s with identity %s\n", electOps.Name, identityKey)

	// Function to generate a new LeaseLock
	generateNewLock := func() *resourcelock.LeaseLock {
		return &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      electOps.Name,
				Namespace: electOps.Namespace,
			},
			Client: client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: identityKey,
			},
		}
	}

	// Function to handle the leader election process
	var startLeaderElection func()
	startLeaderElection = func() {
		lock := generateNewLock()
		leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
			Lock:          lock,
			LeaseDuration: electOps.LeaseDuration,
			RenewDeadline: electOps.LeaseDuration / 2,
			RetryPeriod:   electOps.LeaseDuration / 10,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: runner,
				OnStoppedLeading: func() {
					if cancel != nil {
						cancel()
					}
					log.Fatalf("Leadership lost...")
				},
			},
		})
	}

	// Start the leader election process
	startLeaderElection()
	return nil
}
