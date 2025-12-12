module github.com/absfs/smbfs

go 1.23

require (
	github.com/absfs/absfs v0.0.0-20251208232938-aa0ca30de832
	github.com/absfs/fstesting v0.0.0-20251207022242-d748a85c4a1e
	github.com/absfs/memfs v0.0.0-20251208234552-baa4e3ef7566
	github.com/hirochachacha/go-smb2 v1.1.0
	golang.org/x/crypto v0.28.0
)

require (
	github.com/absfs/inode v0.0.0-20251208170702-9db24ab95ae4 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
)

replace (
	github.com/absfs/absfs => ../absfs
	github.com/absfs/fstesting => ../fstesting
	github.com/absfs/fstools => ../fstools
	github.com/absfs/inode => ../inode
	github.com/absfs/lockfs => ../lockfs
	github.com/absfs/memfs => ../memfs
)
