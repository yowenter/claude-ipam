package store

import (
	"context"

	"github.com/yowenter/claude-ipam/pkg/types"
)

type Store interface {
	Create(ctx context.Context, obj *types.KVPair) (*types.KVPair, error) // data, revision
	Get(ctx context.Context, key, revision string) (*types.KVPair, error)
	List(ctx context.Context, key, revision string) (*types.KVPairList, error)
	Delete(ctx context.Context, key, revision string) (*types.KVPair, error)
	Update(ctx context.Context, obj *types.KVPair) (*types.KVPair, error) // 会比较当前的 revision，如果数据库版本较高，则更新失败
	Save(ctx context.Context, data types.KeyData) (*types.KVPair, error)
}
