package etcd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/mvccpb"
	"go.etcd.io/etcd/client/pkg/v3/srv"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"

	model "github.com/yowenter/claude-ipam/pkg/types"
)

var (
	clientTimeout    = 10 * time.Second
	keepaliveTime    = 30 * time.Second
	keepaliveTimeout = 10 * time.Second
)

type EtcdClient struct {
	client *clientv3.Client
}
type EtcdConfig struct {
	EtcdEndpoints    string `json:"etcdEndpoints" envconfig:"ETCD_ENDPOINTS"`
	EtcdDiscoverySrv string `json:"etcdDiscoverySrv" envconfig:"ETCD_DISCOVERY_SRV"`
	EtcdUsername     string `json:"etcdUsername" envconfig:"ETCD_USERNAME"`
	EtcdPassword     string `json:"etcdPassword" envconfig:"ETCD_PASSWORD"`
	EtcdKeyFile      string `json:"etcdKeyFile" envconfig:"ETCD_KEY_FILE"`
	EtcdCertFile     string `json:"etcdCertFile" envconfig:"ETCD_CERT_FILE"`
	EtcdCACertFile   string `json:"etcdCACertFile" envconfig:"ETCD_CA_CERT_FILE"`

	// These config file parameters are to support inline certificates, keys and CA / Trusted certificate.
	// There are no corresponding environment variables to avoid accidental exposure.
	EtcdKey    string `json:"etcdKey" ignored:"true"`
	EtcdCert   string `json:"etcdCert" ignored:"true"`
	EtcdCACert string `json:"etcdCACert" ignored:"true"`
}

func NewEtcdV3Client(config *EtcdConfig) (*EtcdClient, error) {
	if config.EtcdEndpoints != "" && config.EtcdDiscoverySrv != "" {
		log.Warning("Multiple etcd endpoint discovery methods specified in etcdv3 API config")
		return nil, errors.New("multiple discovery or bootstrap options specified, use either \"etcdEndpoints\" or \"etcdDiscoverySrv\"")
	}

	// Split the endpoints into a location slice.
	var etcdLocation []string
	if config.EtcdEndpoints != "" {
		etcdLocation = strings.Split(config.EtcdEndpoints, ",")
	}

	if config.EtcdDiscoverySrv != "" {
		srvs, srvErr := srv.GetClient("etcd-client", config.EtcdDiscoverySrv, "")
		if srvErr != nil {
			return nil, fmt.Errorf("failed to discover etcd endpoints through SRV discovery: %v", srvErr)
		}
		etcdLocation = srvs.Endpoints
	}

	if len(etcdLocation) == 0 {
		log.Warning("No etcd endpoints specified in etcdv3 API config")
		return nil, errors.New("no etcd endpoints specified")
	}

	haveInline := config.EtcdCert != "" || config.EtcdKey != "" || config.EtcdCACert != ""
	haveFiles := config.EtcdCertFile != "" || config.EtcdKeyFile != "" || config.EtcdCACertFile != ""

	if haveInline && haveFiles {
		return nil, fmt.Errorf("Cannot mix inline certificate-key and certificate / key files")
	}

	// Create the etcd client
	// If Etcd Certificate and Key are provided inline through command line agrument,
	// then the inline values take precedence over the ones in the config file.
	// All the three parametes, Certificate, key and CA certificate are to be provided inline for processing.
	var tls *tls.Config
	var err error

	if haveInline {
		tlsInfo := &TlsInlineCertKey{
			CACert: config.EtcdCACert,
			Cert:   config.EtcdCert,
			Key:    config.EtcdKey,
		}
		tls, err = tlsInfo.ClientConfigInlineCertKey()
	} else {
		tlsInfo := &transport.TLSInfo{
			TrustedCAFile: config.EtcdCACertFile,
			CertFile:      config.EtcdCertFile,
			KeyFile:       config.EtcdKeyFile,
		}
		tls, err = tlsInfo.ClientConfig()
	}

	if err != nil {
		return nil, fmt.Errorf("could not initialize etcdv3 client: %+v", err)
	}

	// Build the etcdv3 config.
	cfg := clientv3.Config{
		Endpoints:            etcdLocation,
		TLS:                  tls,
		DialTimeout:          clientTimeout,
		DialKeepAliveTime:    keepaliveTime,
		DialKeepAliveTimeout: keepaliveTimeout,
	}

	// Plumb through the username and password if both are configured.
	if config.EtcdUsername != "" && config.EtcdPassword != "" {
		cfg.Username = config.EtcdUsername
		cfg.Password = config.EtcdPassword
	}

	client, err := clientv3.New(cfg)
	if err != nil {
		return nil, err
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	_, err = client.Status(timeoutCtx, etcdLocation[0])
	if err != nil {
		return nil, err
	}

	return &EtcdClient{client: client}, nil
}

func (c *EtcdClient) Create(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	logCxt := log.WithFields(log.Fields{"model-etcdKey": d.Key, "value": d.Value, "rev": d.Revision})

	// Checking for 0 version of the etcdKey, which means it doesn't exists yet,
	// and if it does, get the current value.
	logCxt.Debug("Performing etcdv3 transaction for Create request")
	txnResp, err := c.client.Txn(ctx).If(
		clientv3.Compare(clientv3.Version(d.Key), "=", 0),
	).Then(
		clientv3.OpPut(d.Key, d.Value),
	).Else(
	// 如果 key 存在，则报错。
	//clientv3.OpGet(d.Key),
	).Commit()
	if err != nil {
		logCxt.WithError(err).Warning("Create failed")
		return nil, err
	}

	if !txnResp.Succeeded {
		// The resource must already exist.  Extract the current newValue and
		// return that if possible.
		logCxt.Warn("Create transaction failed due to resource already existing")
		if len(txnResp.Responses) == 0 {
			return nil, errors.New("KEY EXISTS:" + d.Key)
		}
		var existing *model.KVPair
		getResp := (*clientv3.GetResponse)(txnResp.Responses[0].GetResponseRange())
		if len(getResp.Kvs) != 0 {
			existing, _ = etcdToKVPair(getResp.Kvs[0])
		}
		return existing, err
	}

	d.Revision = strconv.FormatInt(txnResp.Header.Revision, 10)

	return d, nil

}
func (c *EtcdClient) Get(ctx context.Context, key, revision string) (*model.KVPair, error) {
	logCxt := log.WithFields(log.Fields{"model-etcdKey": key, "rev": revision})

	var ops []clientv3.OpOption
	if len(revision) != 0 {
		rev, err := parseRevision(revision)
		if err != nil {
			return nil, err
		}
		ops = append(ops, clientv3.WithRev(rev))
	}

	logCxt.Debug("Calling Get on etcdv3 client")
	resp, err := c.client.Get(ctx, key, ops...)
	if err != nil {
		logCxt.WithError(err).Debug("Error returned from etcdv3 client")
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		logCxt.Debug("No results returned from etcdv3 client")
		return nil, errors.New("NOT FOUND")
	}

	return etcdToKVPair(resp.Kvs[0])

}
func (c *EtcdClient) List(ctx context.Context, key, revision string) (*model.KVPairList, error) {
	logCxt := log.WithFields(log.Fields{"rev": revision})

	// To list entries, we enumerate from the common root based on the supplied IDs, and then filter the results.

	logCxt = logCxt.WithField("etcdv3-etcdKey", key)
	var ops []clientv3.OpOption
	// We may also need to perform a get based on a particular revision.
	if len(revision) != 0 {
		rev, err := parseRevision(revision)
		if err != nil {
			return nil, err
		}
		ops = append(ops, clientv3.WithRev(rev))
	}
	ops = append(ops, clientv3.WithPrefix())

	resp, err := c.client.Get(ctx, key, ops...)
	if err != nil {
		logCxt.WithError(err).Debug("Error returned from etcdv3 client")
		return nil, err
	}
	logCxt.WithField("numResults", len(resp.Kvs)).Debug("Processing response from etcdv3")

	// Filter/process the results.
	var list []*model.KVPair
	for _, p := range resp.Kvs {
		if kv, err := etcdToKVPair(p); err == nil {
			list = append(list, kv)
		}
	}

	// If we're listing profiles, we need to handle the statically defined
	// default-allow profile in the resources package.
	// We always include the default profile.
	return &model.KVPairList{
		KVPairs:  list,
		Revision: strconv.FormatInt(resp.Header.Revision, 10),
	}, nil

}
func (c *EtcdClient) Update(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	logCxt := log.WithFields(log.Fields{"model-etcdKey": d.Key, "value": d.Value, "rev": d.Revision})
	//logCxt.Debug("Processing Update request")

	logCxt = logCxt.WithField("etcdv3-etcdKey", d.Key)

	opts := []clientv3.OpOption{}
	// We may also need to perform a get based on a particular revision.
	// if len(d.Revision) != 0 {
	// 	rev, err := parseRevision(d.Revision)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	opts = append(opts, clientv3.WithRev(rev))
	// }
	// ResourceVersion must be set for an Update.
	rev, err := parseRevision(d.Revision)
	if err != nil {
		return nil, err
	}
	conds := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(d.Key), "=", rev)}

	logCxt.Debug("Performing etcdv3 transaction for Update request")
	txnResp, err := c.client.Txn(ctx).If(
		conds...,
	).Then(
		clientv3.OpPut(d.Key, d.Value, opts...),
	).Else().Commit()

	if err != nil {
		logCxt.WithError(err).Warning("Update failed")
		return nil, err
	}

	// Etcd V3 does not return an error when compare condition fails we must verify the
	// response Succeeded field instead.  If the compare did not succeed then check for
	// a successful get to return either an UpdateConflict or a ResourceDoesNotExist error.
	if !txnResp.Succeeded {
		if len(txnResp.Responses) == 0 {
			// 如果没有返回，说明更新不成功。
			log.Warn("update on outdated resource", d)
			return nil, errors.New("UPDATE ON OUTDATED RESOURCE")
		}
		getResp := (*clientv3.GetResponse)(txnResp.Responses[0].GetResponseRange())
		if len(getResp.Kvs) == 0 {
			logCxt.Debug("Update transaction failed due to resource not existing")
			return nil, err
		}

		logCxt.Warn("Update transaction failed due to resource update conflict")
		existing, _ := etcdToKVPair(getResp.Kvs[0])
		return existing, err
	}

	d.Revision = strconv.FormatInt(txnResp.Header.Revision, 10)

	return d, nil

}
func (c *EtcdClient) Delete(ctx context.Context, key, revision string) (*model.KVPair, error) {
	logCxt := log.WithFields(log.Fields{"model-etcdKey": key, "rev": revision})
	//logCxt.Debug("Processing Delete request")

	logCxt = logCxt.WithField("etcdv3-etcdKey", key)

	conds := []clientv3.Cmp{}
	if len(revision) != 0 {
		rev, err := parseRevision(revision)
		if err != nil {
			return nil, err
		}
		conds = append(conds, clientv3.Compare(clientv3.ModRevision(key), "=", rev))
	}

	// Perform the delete transaction - note that this is an exact delete, not a prefix delete.
	logCxt.Debug("Performing etcdv3 transaction for Delete request")
	txnResp, err := c.client.Txn(ctx).If(
		conds...,
	).Then(
		clientv3.OpDelete(key, clientv3.WithPrevKV()),
	).Else(
	//clientv3.OpGet(key),
	).Commit()
	if err != nil {
		logCxt.WithError(err).Warning("Delete failed")
		return nil, err
	}

	// Transaction did not succeed - which means the ModifiedIndex check failed.  We can respond
	// with the latest settings.
	if !txnResp.Succeeded {
		logCxt.Warn("Delete transaction failed due to resource update conflict", key)
		if len(txnResp.Responses) == 0 {
			// 如果没有返回，说明更新不成功。
			return nil, errors.New("DELETE ON OUTDATED RESOURCE")
		}

		getResp := txnResp.Responses[0].GetResponseRange()
		if len(getResp.Kvs) == 0 {
			logCxt.Debug("Delete transaction failed due to resource not existing")
			return nil, errors.New("NOT FOUND")
		}
		latestValue, err := etcdToKVPair(getResp.Kvs[0])
		if err != nil {
			return nil, err
		}
		return latestValue, errors.New("CONFLICT")
	}

	// The delete response should have succeeded since the Get response did.
	delResp := txnResp.Responses[0].GetResponseDeleteRange()
	if delResp.Deleted == 0 {
		logCxt.Debug("Delete transaction failed due to resource not existing")
		return nil, errors.New("NOT FOUND")
	}

	// Parse the deleted value.  Don't propagate the error in this case since the
	// delete did succeed.
	previousValue, _ := etcdToKVPair(delResp.PrevKvs[0])
	return previousValue, nil
}

func (c *EtcdClient) Save(ctx context.Context, data model.KeyData) (*model.KVPair, error) {
	data.UpdateTs()
	kv, err := data.Serialize()
	if err != nil {
		return nil, err
	}

	if kv.Revision == "" {
		return c.Create(ctx, kv)
	}
	return c.Update(ctx, kv)

}

// etcdToKVPair converts an etcd KeyValue in to model.KVPair.
func etcdToKVPair(ekv *mvccpb.KeyValue) (*model.KVPair, error) {
	if ekv == nil {
		return nil, fmt.Errorf("none")
	}
	return &model.KVPair{
		Key:      string(ekv.Key),
		Value:    string(ekv.Value),
		Revision: strconv.FormatInt(ekv.ModRevision, 10),
	}, nil
}

// parseRevision parses the model.KVPair revision string and converts to the
// equivalent etcdv3 int64 value.
func parseRevision(revs string) (int64, error) {
	rev, err := strconv.ParseInt(revs, 10, 64)
	if err != nil {
		log.WithField("Revision", revs).Debug("Unable to parse Revision")
		return 0, err
	}
	return rev, nil
}

func (c *EtcdClient) Client() *clientv3.Client {
	return c.client
}
