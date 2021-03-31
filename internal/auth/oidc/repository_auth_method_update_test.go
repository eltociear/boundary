package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/sdk/testutil"
	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_UpdateAuthMethod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	tp := oidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()
	tpCert, err := ParseCertificates(tp.CACert())
	require.NoError(t, err)
	require.Equal(t, 1, len(tpCert))

	rw := db.New(conn)
	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)

	tests := []struct {
		name             string
		setup            func() *AuthMethod
		updateWith       func(orig *AuthMethod) *AuthMethod
		fieldMasks       []string
		version          uint32
		opt              []Option
		want             func(orig, updateWith *AuthMethod) *AuthMethod
		wantErrMatch     *errors.Template
		wantNoRowsUpdate bool
	}{
		{
			name: "very-simple",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.AudClaims = []string{"www.alice.com", "www.alice.com/admin"}
				return &am
			},
			fieldMasks: []string{"Name", "Description", "AudClaims"},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.AudClaims = updateWith.AudClaims
				return am
			},
		},
		{
			name: "with-force-all-value-objects",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithAudClaims("www.alice.com"),
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				_, pem := testGenerateCA(t, "127.0.0.1")
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.AudClaims = []string{"www.alice.com/admin"}
				am.CallbackUrls = []string{"https://www.bob.com/callback"}
				am.SigningAlgs = []string{string(ES384), string(ES512)}
				am.Certificates = []string{pem}
				return &am
			},
			fieldMasks: []string{"Name", "Description", "AudClaims", "CallbackUrls", "SigningAlgs", "Certificates"},
			version:    1,
			opt:        []Option{WithForce()},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.AudClaims = updateWith.AudClaims
				am.CallbackUrls = updateWith.CallbackUrls
				am.SigningAlgs = updateWith.SigningAlgs
				am.Certificates = updateWith.Certificates
				am.DisableDiscoveredConfigValidation = true
				return am
			},
		},
		{
			name: "null-name-description",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithName("alice's restaurant"),
					WithDescription("the best place to eat"),
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = ""
				am.Description = ""
				return &am
			},
			fieldMasks: []string{"Name", "Description"},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = ""
				am.Description = ""
				return am
			},
		},
		{
			name: "null-signing-algs",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				return &am
			},
			fieldMasks: []string{"SigningAlgs"},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.SigningAlgs = nil
				return am
			},
		},
		{
			name: "change-callback-url",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.CallbackUrls = []string{"https://www.updated.com/callback"}
				return &am
			},
			fieldMasks: []string{"CallbackUrls"},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.CallbackUrls = updateWith.CallbackUrls
				return am
			},
		},
		{
			name: "no-changes",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.SigningAlgs = []string{string(tpAlg)}
				return &am
			},
			fieldMasks: []string{"SigningAlgs"},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				return am
			},
			wantNoRowsUpdate: true,
		},
		{
			name: "inactive-not-complete-no-with-force",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.AudClaims = []string{"www.alice.com", "www.alice.com/admin"}
				return &am
			},
			fieldMasks: []string{"Name", "Description", "AudClaims"},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.AudClaims = updateWith.AudClaims
				return am
			},
		},
		{
			name: "with-dry-run",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithAudClaims("www.alice.com"),
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.AudClaims = []string{"www.alice.com/admin"}
				am.CallbackUrls = []string{"https://www.bob.com/callback"}
				am.SigningAlgs = []string{string(ES384), string(ES512)}
				return &am
			},
			fieldMasks: []string{"Name", "Description", "AudClaims", "CallbackUrls", "SigningAlgs"},
			version:    1,
			opt:        []Option{WithDryRun()},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.AudClaims = updateWith.AudClaims
				am.CallbackUrls = updateWith.CallbackUrls
				am.SigningAlgs = updateWith.SigningAlgs
				return am
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:         "nil-authMethod",
			setup:        func() *AuthMethod { return nil },
			updateWith:   func(orig *AuthMethod) *AuthMethod { return nil },
			fieldMasks:   []string{"Name"},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:         "nil-authMethod-store",
			setup:        func() *AuthMethod { return nil },
			updateWith:   func(orig *AuthMethod) *AuthMethod { return &AuthMethod{} },
			fieldMasks:   []string{"Name"},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:         "missing-public-id",
			setup:        func() *AuthMethod { return nil },
			updateWith:   func(orig *AuthMethod) *AuthMethod { a := AllocAuthMethod(); return &a },
			fieldMasks:   []string{"Name"},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:  "bad-field-mask",
			setup: func() *AuthMethod { return nil },
			updateWith: func(orig *AuthMethod) *AuthMethod {
				a := AllocAuthMethod()
				id, _ := newAuthMethodId()
				a.PublicId = id
				return &a
			},
			fieldMasks:   []string{"CreateTime"},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:  "no-mask-or-null-fields",
			setup: func() *AuthMethod { return nil },
			updateWith: func(orig *AuthMethod) *AuthMethod {
				a := AllocAuthMethod()
				id, _ := newAuthMethodId()
				a.PublicId = id
				return &a
			},
			version:      1,
			wantErrMatch: errors.T(errors.EmptyFieldMask),
		},
		{
			name:  "not-found",
			setup: func() *AuthMethod { return nil },
			updateWith: func(orig *AuthMethod) *AuthMethod {
				a := AllocAuthMethod()
				id, _ := newAuthMethodId()
				a.PublicId = id
				return &a
			},
			fieldMasks:   []string{"Name"},
			version:      1,
			wantErrMatch: errors.T(errors.RecordNotFound),
		},
		{
			name: "bad-version",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithAudClaims("www.alice.com"),
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				return &am
			},
			fieldMasks:   []string{"Name"},
			version:      100,
			wantErrMatch: errors.T(errors.VersionMismatch),
		},
		{
			name: "not-valid-auth-method",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithAudClaims("www.alice.com"),
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.SigningAlgs = []string{string(ES384), string(ES512)}
				return &am
			},
			fieldMasks:   []string{"Name", "Description", "SigningAlgs"},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "active-with-update-to-incomplete",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					ActivePublicState,
					TestConvertToUrls(t, tp.Addr())[0],
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				return &am
			},
			fieldMasks:   []string{"SigningAlgs"},
			version:      2, // since TestAuthMethod(...) did an update to get it to ActivePublicState
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := tt.setup()
			updateWith := tt.updateWith(orig)
			updated, rowsUpdated, err := repo.UpdateAuthMethod(ctx, updateWith, tt.version, tt.fieldMasks, tt.opt...)
			opts := getOpts(tt.opt...)
			if tt.wantErrMatch != nil && !opts.withDryRun {
				require.Error(err)
				assert.Equal(0, rowsUpdated)
				assert.Nil(updated)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)

				if updateWith != nil && updateWith.AuthMethod != nil && updateWith.PublicId != "" {
					err := db.TestVerifyOplog(t, rw, updateWith.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
					require.Errorf(err, "should not have found oplog entry for %s", updateWith.PublicId)
				}
				return
			}
			switch opts.withDryRun {
			case true:
				assert.Equal(0, rowsUpdated)
				switch tt.wantErrMatch != nil {
				case true:
					require.Error(err)
				default:
					require.NoError(err)
				}
				require.NotNil(updated)
				want := tt.want(orig, updateWith)
				want.CreateTime = orig.CreateTime
				want.UpdateTime = orig.UpdateTime
				want.Version = orig.Version
				TestSortAuthMethods(t, []*AuthMethod{want, updated})
				assert.Equal(want, updated)

				err := db.TestVerifyOplog(t, rw, updateWith.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Errorf(err, "should not have found oplog entry for %s", updateWith.PublicId)
			default:
				require.NoError(err)
				require.NotNil(updated)
				want := tt.want(orig, updateWith)
				want.CreateTime = updated.CreateTime
				want.UpdateTime = updated.UpdateTime
				want.Version = updated.Version
				TestSortAuthMethods(t, []*AuthMethod{want, updated})
				assert.Empty(cmp.Diff(updated.AuthMethod, want.AuthMethod, protocmp.Transform()))
				if !tt.wantNoRowsUpdate {
					assert.Equal(1, rowsUpdated)
					err = db.TestVerifyOplog(t, rw, updateWith.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
					require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
				}
			}
		})
	}
}

func Test_ValidateDiscoveryInfo(t *testing.T) {
	// do not run these tests with t.Parallel()
	ctx := context.Background()

	tp := oidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()
	tpCert, err := ParseCertificates(tp.CACert())
	require.NoError(t, err)
	require.Equal(t, 1, len(tpCert))

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)
	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	port := testutil.TestFreePort(t)
	testAuthMethodCallback, err := url.Parse(fmt.Sprintf("http://localhost:%d/callback", port))
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(t,
		conn, databaseWrapper,
		org.PublicId,
		ActivePrivateState,
		TestConvertToUrls(t, tp.Addr())[0],
		tpClientId, ClientSecret(tpClientSecret),
		WithCertificates(tpCert[0]),
		WithSigningAlgs(Alg(tpAlg)),
		WithCallbackUrls(testAuthMethodCallback),
	)
	tests := []struct {
		name            string
		setup           func()
		cleanup         func()
		authMethod      *AuthMethod
		withAuthMethod  bool
		withPublicId    bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:           "simple-and-valid",
			authMethod:     testAuthMethod,
			withAuthMethod: true,
		},
		{
			name:         "simple-and-valid",
			authMethod:   testAuthMethod,
			withPublicId: true,
		},
		{
			name:         "missing-withPublicId-or-withAuthMethod",
			authMethod:   testAuthMethod,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:            "not-complete",
			authMethod:      func() *AuthMethod { cp := testAuthMethod.Clone(); cp.SigningAlgs = nil; return cp }(),
			withAuthMethod:  true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: " missing signing algorithms",
		},
		{
			name: "no-discovery",
			authMethod: func() *AuthMethod {
				cp := testAuthMethod.Clone()
				port := testutil.TestFreePort(t)
				cp.DiscoveryUrl = fmt.Sprintf("http://localhost:%d", port)
				return cp
			}(),
			withAuthMethod:  true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "AuthMethod cannot be converted to a valid OIDC Provider",
		},
		{
			name:            "fail-jwks",
			setup:           func() { tp.SetDisableJWKs(true) },
			cleanup:         func() { tp.SetDisableJWKs(false) },
			authMethod:      testAuthMethod,
			withAuthMethod:  true,
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "non-200",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var opts []Option
			switch {
			case tt.withAuthMethod:
				opts = append(opts, WithAuthMethod(tt.authMethod))
			case tt.withPublicId:
				opts = append(opts, WithPublicId(tt.authMethod.PublicId))
			}
			if tt.setup != nil {
				tt.setup()
				defer tt.cleanup()
			}
			err := repo.ValidateDiscoveryInfo(ctx, opts...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)
				if tt.wantErrContains != "" {
					assert.Containsf(err.Error(), tt.wantErrContains, "want err to contain %s got: %s", tt.wantErrContains, err.Error())
				}
				return
			}
			require.NoError(err)
		})
	}
}

func Test_valueObjectChanges(t *testing.T) {
	t.Parallel()
	_, pem1 := testGenerateCA(t, "localhost")
	_, pem2 := testGenerateCA(t, "127.0.0.1")
	_, pem3 := testGenerateCA(t, "www.example.com")
	tests := []struct {
		name         string
		id           string
		voName       voName
		new          []string
		old          []string
		dbMask       []string
		nullFields   []string
		wantAdd      []interface{}
		wantDel      []interface{}
		wantErrMatch *errors.Template
	}{
		{
			name:   string(SigningAlgVO),
			id:     "am-public-id",
			voName: SigningAlgVO,
			new:    []string{"ES256", "ES384"},
			old:    []string{"RS256", "RS384", "RS512"},
			dbMask: []string{string(SigningAlgVO)},
			wantAdd: func() []interface{} {
				a, err := NewSigningAlg("am-public-id", ES256)
				require.NoError(t, err)
				a2, err := NewSigningAlg("am-public-id", ES384)
				require.NoError(t, err)
				return []interface{}{a, a2}
			}(),
			wantDel: func() []interface{} {
				a, err := NewSigningAlg("am-public-id", RS256)
				require.NoError(t, err)
				a2, err := NewSigningAlg("am-public-id", RS384)
				require.NoError(t, err)
				a3, err := NewSigningAlg("am-public-id", RS512)
				require.NoError(t, err)
				return []interface{}{a, a2, a3}
			}(),
		},
		{
			name:   string(CertificateVO),
			id:     "am-public-id",
			voName: CertificateVO,
			new:    []string{pem1, pem2},
			old:    []string{pem3},
			dbMask: []string{string(CertificateVO)},
			wantAdd: func() []interface{} {
				c, err := NewCertificate("am-public-id", pem1)
				require.NoError(t, err)
				c2, err := NewCertificate("am-public-id", pem2)
				require.NoError(t, err)
				return []interface{}{c, c2}
			}(),
			wantDel: func() []interface{} {
				c, err := NewCertificate("am-public-id", pem3)
				require.NoError(t, err)
				return []interface{}{c}
			}(),
		},
		{
			name:   string(AudClaimVO),
			id:     "am-public-id",
			voName: AudClaimVO,
			new:    []string{"new-aud1", "new-aud2"},
			old:    []string{"old-aud1", "old-aud2", "old-aud3"},
			dbMask: []string{string(AudClaimVO)},
			wantAdd: func() []interface{} {
				a, err := NewAudClaim("am-public-id", "new-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim("am-public-id", "new-aud2")
				require.NoError(t, err)
				return []interface{}{a, a2}
			}(),
			wantDel: func() []interface{} {
				a, err := NewAudClaim("am-public-id", "old-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim("am-public-id", "old-aud2")
				require.NoError(t, err)
				a3, err := NewAudClaim("am-public-id", "old-aud3")
				require.NoError(t, err)
				return []interface{}{a, a2, a3}
			}(),
		},
		{
			name:   string(CallbackUrlVO),
			id:     "am-public-id",
			voName: CallbackUrlVO,
			new:    []string{"http://new-1.com/callback", "http://new-2.com/callback"},
			old:    []string{"http://old-1.com/callback", "http://old-2.com/callback", "http://old-3.com/callback"},
			dbMask: []string{string(CallbackUrlVO)},
			wantAdd: func() []interface{} {
				u, err := url.Parse("http://new-1.com/callback")
				require.NoError(t, err)
				c, err := NewCallbackUrl("am-public-id", u)
				require.NoError(t, err)
				u2, err := url.Parse("http://new-2.com/callback")
				require.NoError(t, err)
				c2, err := NewCallbackUrl("am-public-id", u2)
				require.NoError(t, err)
				return []interface{}{c, c2}
			}(),
			wantDel: func() []interface{} {
				u, err := url.Parse("http://old-1.com/callback")
				require.NoError(t, err)
				c, err := NewCallbackUrl("am-public-id", u)
				require.NoError(t, err)
				u2, err := url.Parse("http://old-2.com/callback")
				require.NoError(t, err)
				c2, err := NewCallbackUrl("am-public-id", u2)
				require.NoError(t, err)
				u3, err := url.Parse("http://old-3.com/callback")
				require.NoError(t, err)
				c3, err := NewCallbackUrl("am-public-id", u3)
				require.NoError(t, err)
				return []interface{}{c, c2, c3}
			}(),
		},

		{
			name:       string(AudClaimVO) + "-null-fields",
			id:         "am-public-id",
			voName:     AudClaimVO,
			new:        nil,
			old:        []string{"old-aud1", "old-aud2", "old-aud3"},
			nullFields: []string{string(AudClaimVO)},
			wantDel: func() []interface{} {
				a, err := NewAudClaim("am-public-id", "old-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim("am-public-id", "old-aud2")
				require.NoError(t, err)
				a3, err := NewAudClaim("am-public-id", "old-aud3")
				require.NoError(t, err)
				return []interface{}{a, a2, a3}
			}(),
		},
		{
			name:       "missing-public-id",
			voName:     AudClaimVO,
			new:        nil,
			old:        []string{"old-aud1", "old-aud2", "old-aud3"},
			nullFields: []string{string(AudClaimVO)},
			wantDel: func() []interface{} {
				a, err := NewAudClaim("am-public-id", "old-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim("am-public-id", "old-aud2")
				require.NoError(t, err)
				a3, err := NewAudClaim("am-public-id", "old-aud3")
				require.NoError(t, err)
				return []interface{}{a, a2, a3}
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:       "invalid-vo-name",
			voName:     voName("invalid-name"),
			id:         "am-public-id",
			new:        nil,
			old:        []string{"old-aud1", "old-aud2", "old-aud3"},
			nullFields: []string{string(AudClaimVO)},
			wantDel: func() []interface{} {
				a, err := NewAudClaim("am-public-id", "old-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim("am-public-id", "old-aud2")
				require.NoError(t, err)
				a3, err := NewAudClaim("am-public-id", "old-aud3")
				require.NoError(t, err)
				return []interface{}{a, a2, a3}
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:   "dup-new",
			id:     "am-public-id",
			voName: SigningAlgVO,
			new:    []string{"ES256", "ES256"},
			old:    []string{"RS256", "RS384", "RS512"},
			dbMask: []string{string(SigningAlgVO)},
			wantAdd: func() []interface{} {
				a, err := NewSigningAlg("am-public-id", ES256)
				require.NoError(t, err)
				a2, err := NewSigningAlg("am-public-id", ES384)
				require.NoError(t, err)
				return []interface{}{a, a2}
			}(),
			wantDel: func() []interface{} {
				a, err := NewSigningAlg("am-public-id", RS256)
				require.NoError(t, err)
				a2, err := NewSigningAlg("am-public-id", RS384)
				require.NoError(t, err)
				a3, err := NewSigningAlg("am-public-id", RS512)
				require.NoError(t, err)
				return []interface{}{a, a2, a3}
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:   "dup-old",
			id:     "am-public-id",
			voName: SigningAlgVO,
			new:    []string{"ES256", "ES384"},
			old:    []string{"RS256", "RS256", "RS512"},
			dbMask: []string{string(SigningAlgVO)},
			wantAdd: func() []interface{} {
				a, err := NewSigningAlg("am-public-id", ES256)
				require.NoError(t, err)
				a2, err := NewSigningAlg("am-public-id", ES384)
				require.NoError(t, err)
				return []interface{}{a, a2}
			}(),
			wantDel: func() []interface{} {
				a, err := NewSigningAlg("am-public-id", RS256)
				require.NoError(t, err)
				a2, err := NewSigningAlg("am-public-id", RS384)
				require.NoError(t, err)
				a3, err := NewSigningAlg("am-public-id", RS512)
				require.NoError(t, err)
				return []interface{}{a, a2, a3}
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotAdd, gotDel, err := valueObjectChanges(tt.id, tt.voName, tt.new, tt.old, tt.dbMask, tt.nullFields)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantAdd, gotAdd)

			switch tt.voName {
			case CertificateVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*Certificate).Cert < bb.(*Certificate).Cert
				})
			case SigningAlgVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*SigningAlg).Alg < bb.(*SigningAlg).Alg
				})
			case CallbackUrlVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*CallbackUrl).Url < bb.(*CallbackUrl).Url
				})
			case AudClaimVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*AudClaim).Aud < bb.(*AudClaim).Aud
				})
			}
			assert.Equalf(tt.wantDel, gotDel, "wantDel: %s\ngotDel:  %s\n", tt.wantDel, gotDel)
		})
	}
}

func Test_validateFieldMask(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		fieldMask []string
		wantErr   bool
	}{
		{
			name: "all-valid-fields",
			fieldMask: []string{
				"Name",
				"Description",
				"DiscoveryUrl",
				"ClientId",
				"ClientSecret",
				"MaxAge",
				"SigningAlgs",
				"CallbackUrls",
				"AudClaims",
				"Certificates",
			},
		},
		{
			name:      "invalid",
			fieldMask: []string{"Invalid", "Name"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			err := validateFieldMask(tt.fieldMask)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
		})
	}
}

func Test_applyUpdate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		new       *AuthMethod
		orig      *AuthMethod
		fieldMask []string
		want      *AuthMethod
	}{
		{
			name: "valid-all-fields",
			new: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(ActivePublicState),
					DiscoveryUrl:     "new-discovery-url",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"new-alg1", "new-alg2"},
					CallbackUrls:     []string{"new-callback-1", "new-callback-2"},
					AudClaims:        []string{"new-aud-1", "new-aud-2"},
					Certificates:     []string{"new-pem1", "new-pem-2"},
				},
			},
			orig: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "orig-name",
					Description:      "orig-description",
					OperationalState: string(InactiveState),
					DiscoveryUrl:     "orig-discovery-url",
					ClientId:         "orig-client-id",
					ClientSecret:     "orig-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"orig-alg1", "orig-alg2"},
					CallbackUrls:     []string{"orig-callback-1", "orig-callback-2"},
					AudClaims:        []string{"orig-aud-1", "orig-aud-2"},
					Certificates:     []string{"orig-pem1", "orig-pem-2"},
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(InactiveState),
					DiscoveryUrl:     "new-discovery-url",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"new-alg1", "new-alg2"},
					CallbackUrls:     []string{"new-callback-1", "new-callback-2"},
					AudClaims:        []string{"new-aud-1", "new-aud-2"},
					Certificates:     []string{"new-pem1", "new-pem-2"},
				},
			},
			fieldMask: []string{
				"Name",
				"Description",
				"DiscoveryUrl",
				"ClientId",
				"ClientSecret",
				"MaxAge",
				"SigningAlgs",
				"CallbackUrls",
				"AudClaims",
				"Certificates",
			},
		},
		{
			name: "nil-value-objects",
			new: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(ActivePublicState),
					DiscoveryUrl:     "new-discovery-url",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
				},
			},
			orig: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "orig-name",
					Description:      "orig-description",
					OperationalState: string(InactiveState),
					DiscoveryUrl:     "orig-discovery-url",
					ClientId:         "orig-client-id",
					ClientSecret:     "orig-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"orig-alg1", "orig-alg2"},
					CallbackUrls:     []string{"orig-callback-1", "orig-callback-2"},
					AudClaims:        []string{"orig-aud-1", "orig-aud-2"},
					Certificates:     []string{"orig-pem1", "orig-pem-2"},
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(InactiveState),
					DiscoveryUrl:     "new-discovery-url",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
				},
			},
			fieldMask: []string{
				"Name",
				"Description",
				"DiscoveryUrl",
				"ClientId",
				"ClientSecret",
				"MaxAge",
				"SigningAlgs",
				"CallbackUrls",
				"AudClaims",
				"Certificates",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := applyUpdate(tt.new, tt.orig, tt.fieldMask)
			assert.Equal(got, tt.want)
		})
	}
}

type mockClient struct {
	mockDo func(req *http.Request) (*http.Response, error)
}

// Overriding what the Do function should "do" in our MockClient
func (m *mockClient) Do(req *http.Request) (*http.Response, error) {
	return m.mockDo(req)
}

func Test_pingEndpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name       string
		setup      func() (HTTPClient, string, string)
		wantStatus int
		wantErr    bool
	}{
		{
			name: "valid-endpoint",
			setup: func() (HTTPClient, string, string) {
				client := &mockClient{
					mockDo: func(*http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				}
				return client, http.MethodGet, "http://localhost/get"
			},
			wantStatus: 200,
		},
		{
			name: "valid-500",
			setup: func() (HTTPClient, string, string) {
				client := &mockClient{
					mockDo: func(*http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 500,
						}, nil
					},
				}
				return client, http.MethodGet, "http://localhost/get"
			},
			wantStatus: 500,
		},
		{
			name: "failed",
			setup: func() (HTTPClient, string, string) {
				client := &mockClient{
					mockDo: func(*http.Request) (*http.Response, error) {
						return nil, fmt.Errorf("invalid request")
					},
				}
				return client, http.MethodGet, "http://localhost/get"
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			client, method, url := tt.setup()
			gotStatus, err := pingEndpoint(ctx, client, tt.name, method, url)
			assert.Equal(gotStatus, tt.wantStatus)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
		})
	}
}
