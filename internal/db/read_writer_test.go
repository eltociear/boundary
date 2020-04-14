package db

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db/db_test"
	"github.com/hashicorp/watchtower/internal/oplog"
	"gotest.tools/assert"
)

func Test_Create(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	db_test.Init(conn)
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), &user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		var foundUser db_test.TestUser
		err = w.LookupByInternalId(context.Background(), &foundUser, user.Id)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
	t.Run("valid-WithOplog", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(
			context.Background(),
			user,
			WithOplog(true),
			WithWrapper(InitTestWrapper(t)),
			WithMetadata(oplog.Metadata{
				"key-only":   nil,
				"deployment": []string{"amex"},
				"project":    []string{"central-info-systems", "local-info-systems"},
			}),
		)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		var foundUser db_test.TestUser
		err = w.LookupByInternalId(context.Background(), &foundUser, user.Id)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
}

func Test_LookupByInternalId(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	db_test.Init(conn)
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		err = w.Create(context.Background(), &user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		var foundUser db_test.TestUser
		err = w.LookupByInternalId(context.Background(), &foundUser, user.Id)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
}

func Test_LookupByFriendlyName(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	db_test.Init(conn)
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), &user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)

		var foundUser db_test.TestUser
		err = w.LookupByFriendlyName(context.Background(), &foundUser, "fn-"+id)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
}

func Test_LookupByPublicId(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	db_test.Init(conn)
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), &user)
		assert.NilError(t, err)
		assert.Check(t, user.PublicId != "")

		var foundUser db_test.TestUser
		err = w.LookupByPublicId(context.Background(), &foundUser, user.PublicId)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
}

func Test_LookupBy(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	db_test.Init(conn)
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), &user)
		assert.NilError(t, err)
		assert.Check(t, user.PublicId != "")

		var foundUser db_test.TestUser
		err = w.LookupBy(context.Background(), &foundUser, "public_id = ?", user.PublicId)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUser.Id)
	})
}

func Test_SearchBy(t *testing.T) {
	StartTest()
	t.Parallel()
	cleanup, url := SetupTest(t, "migrations/postgres")
	defer cleanup()
	defer CompleteTest() // must come after the "defer cleanup()"
	conn, err := TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	db_test.Init(conn)
	t.Run("simple", func(t *testing.T) {
		w := GormReadWriter{Tx: conn}
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		user, err := db_test.NewTestUser()
		assert.NilError(t, err)
		user.Name = "foo-" + id
		user.FriendlyName = "fn-" + id
		err = w.Create(context.Background(), &user)
		assert.NilError(t, err)
		assert.Check(t, user.PublicId != "")

		var foundUsers []db_test.TestUser
		err = w.SearchBy(context.Background(), &foundUsers, "public_id = ?", user.PublicId)
		assert.NilError(t, err)
		assert.Equal(t, user.Id, foundUsers[0].Id)
	})
}
