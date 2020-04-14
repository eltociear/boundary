package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/jinzhu/gorm"
	"google.golang.org/protobuf/proto"
)

type Reader interface {
	// LookupByFriendlyName will lookup resource my its friendly_name which must be unique
	LookupByFriendlyName(ctx context.Context, resource interface{}, friendlyName string, opt ...Option) error

	// LookupByPublicId will lookup resource my its public_id which must be unique
	LookupByPublicId(ctx context.Context, resource interface{}, publicId string, opt ...Option) error

	// LookupByInternalId will lookup resource my its internal id which must be unique
	LookupByInternalId(ctx context.Context, resource interface{}, internalId uint32, opt ...Option) error

	// LookupBy will lookup the first resource using a where clause with parameters (it only returns the first one)
	LookupBy(ctx context.Context, resource interface{}, where string, args ...interface{}) error

	// SearchBy will search for all the resources it can find using a where clause with parameters
	SearchBy(ctx context.Context, resources interface{}, where string, args ...interface{}) error

	// DB returns the sql.DB
	DB() (*sql.DB, error)

	// Dialect returns the RDBMS dialect: postgres, mysql, etc
	Dialect() (string, error)
}
type Writer interface {
	// Update an object in the db, if there's a fieldMask then only the field_mask.proto paths are updated, otherwise
	// it will send every field to the DB
	Update(i interface{}, fieldMaskPaths []string, opt ...Option) error

	// Create an object in the db with options: WithOplog (which requires WithMetadata, WithWrapper)
	Create(ctx context.Context, i interface{}, opt ...Option) error

	// CreateConstraint will create a db constraint if it doesn't already exist
	CreateConstraint(tableName string, constraintName string, constraint string) error

	// DB returns the sql.DB
	DB() (*sql.DB, error)

	// Dialect returns the RDBMS dialect: postgres, mysql, etc
	Dialect() (string, error)
}

// GormReadWriter uses a gorm DB connection for read/write
type GormReadWriter struct {
	Tx *gorm.DB
}

// Dialect returns the RDBMS dialect: postgres, mysql, etc
func (rw *GormReadWriter) Dialect() (string, error) {
	if rw.Tx == nil {
		return "", errors.New("create Tx is nil for Dialect")
	}
	return rw.Tx.Dialect().GetName(), nil
}

// DB returns the sql.DB
func (rw *GormReadWriter) DB() (*sql.DB, error) {
	if rw.Tx == nil {
		return nil, errors.New("create Tx is nil for DB")
	}
	return rw.Tx.DB(), nil
}

// gormDB returns a *gorm.DB
func (rw *GormReadWriter) gormDB() (*gorm.DB, error) {
	if rw.Tx == nil {
		return nil, errors.New("create Tx is nil for gormDB")
	}
	dialect, err := rw.Dialect()
	if err != nil {
		return nil, fmt.Errorf("error getting dialect %w for gormDB", err)
	}
	db, err := rw.DB()
	if err != nil {
		return nil, fmt.Errorf("error getting DB %w for gormDB", err)
	}
	return gorm.Open(dialect, db)
}

// CreateConstraint will create a db constraint if it doesn't already exist
func (w *GormReadWriter) CreateConstraint(tableName string, constraintName string, constraint string) error {
	return w.Tx.Exec("create_constraint_if_not_exists(?, ?, ?)", tableName, constraintName, constraint).Error
}

// Create an object in the db with options: WithOplog (which requires WithMetadata, WithWrapper)
func (rw *GormReadWriter) Create(ctx context.Context, i interface{}, opt ...Option) error {
	opts := GetOpts(opt...)
	withOplog := opts[optionWithOplog].(bool)
	if rw.Tx == nil {
		return errors.New("create Tx is nil")
	}
	if i == nil {
		return errors.New("create interface is nil")
	}
	if err := rw.Tx.Create(i).Error; err != nil {
		return fmt.Errorf("error creating: %w", err)
	}
	if withOplog {
		if opts[optionWithWrapper] == nil {
			return errors.New("error wrapper is nil for create WithWrapper")
		}
		withWrapper, ok := opts[optionWithWrapper].(wrapping.Wrapper)
		if !ok {
			return errors.New("error not a wrapping.Wrapper for create WithWrapper")
		}
		withMetadata := opts[optionWithMetadata].(oplog.Metadata)
		if len(withMetadata) == 0 {
			return errors.New("error no metadata for create WithOplog")
		}
		replayable, ok := i.(oplog.ReplayableMessage)
		if !ok {
			return errors.New("error not a replayable message for create WithOplog")
		}
		gdb, err := rw.gormDB()
		if err != nil {
			return fmt.Errorf("error getting underlying gorm DB %w for create WithOplog", err)
		}
		ticketer, err := oplog.NewGormTicketer(gdb, oplog.WithAggregateNames(true))
		if err != nil {
			return fmt.Errorf("error getting Ticketer %w for create WithOplog", err)
		}
		err = ticketer.InitTicket(replayable.TableName())
		if err != nil {
			return fmt.Errorf("error getting initializing ticket %w for create WithOplog", err)
		}
		ticket, err := ticketer.GetTicket(replayable.TableName())
		if err != nil {
			return fmt.Errorf("error getting ticket %w for create WithOplog", err)
		}

		entry, err := oplog.NewEntry(
			replayable.TableName(),
			withMetadata,
			withWrapper,
			ticketer,
		)

		err = entry.WriteEntryWith(
			ctx,
			&oplog.GormWriter{Tx: gdb},
			ticket,
			&oplog.Message{Message: i.(proto.Message), TypeName: replayable.TableName(), OpType: oplog.OpType_CREATE_OP},
		)
		if err != nil {
			return fmt.Errorf("error creating oplog entry %w for create WithOplog", err)
		}
	}
	return nil
}

// Update an object in the db, if there's a fieldMask then only the field_mask.proto paths are updated, otherwise
// it will send every field to the DB.
func (w *GormReadWriter) Update(i interface{}, fieldMaskPaths []string, opt ...Option) error {
	if w.Tx == nil {
		return errors.New("update Tx is nil")
	}
	if i == nil {
		return errors.New("update interface is nil")
	}
	if len(fieldMaskPaths) == 0 {
		if err := w.Tx.Save(i).Error; err != nil {
			return fmt.Errorf("error updating: %w", err)
		}
	}
	updateFields := map[string]interface{}{}

	val := reflect.Indirect(reflect.ValueOf(i))
	structTyp := val.Type()
	for _, field := range fieldMaskPaths {
		for i := 0; i < structTyp.NumField(); i++ {
			// support for an embedded a gorm type
			if structTyp.Field(i).Type.Kind() == reflect.Struct {
				embType := structTyp.Field(i).Type
				// check if the embedded field is exported via CanInterface()
				if val.Field(i).CanInterface() {
					embVal := reflect.Indirect(reflect.ValueOf(val.Field(i).Interface()))
					for embFieldNum := 0; embFieldNum < embType.NumField(); embFieldNum++ {
						if strings.EqualFold(embType.Field(embFieldNum).Name, field) {
							updateFields[field] = embVal.Field(embFieldNum).Interface()
						}
					}
					continue
				}
			}
			// it's not an embedded type, so check if the field name matches
			if strings.EqualFold(structTyp.Field(i).Name, field) {
				updateFields[field] = val.Field(i).Interface()
			}
		}
	}
	if err := w.Tx.Model(i).Updates(updateFields).Error; err != nil {
		return fmt.Errorf("error updating: %w", err)
	}
	return nil
}

// LookupByFriendlyName will lookup resource my its friendly_name which must be unique
func (w *GormReadWriter) LookupByFriendlyName(ctx context.Context, resource interface{}, friendlyName string, opt ...Option) error {
	if w.Tx == nil {
		return errors.New("error db nil for LookupByFriendlyName")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupByFriendlyName")
	}
	if friendlyName == "" {
		return errors.New("error friendlyName empty string for LookupByFriendlyName")
	}
	return w.Tx.Where("friendly_name = ?", friendlyName).First(resource).Error
}

// LookupByPublicId will lookup resource my its public_id which must be unique
func (w *GormReadWriter) LookupByPublicId(ctx context.Context, resource interface{}, publicId string, opt ...Option) error {
	if w.Tx == nil {
		return errors.New("error db nil for LookupByPublicId")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupByPublicId")
	}
	if publicId == "" {
		return errors.New("error publicId empty string for LookupByPublicId")
	}
	return w.Tx.Where("public_id = ?", publicId).First(resource).Error
}

// LookupByInternalId will lookup resource my its internal id which must be unique
func (w *GormReadWriter) LookupByInternalId(ctx context.Context, resource interface{}, internalId uint32, opt ...Option) error {
	if w.Tx == nil {
		return errors.New("error db nil for LookupByInternalId")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupByInternalId")
	}
	if internalId == 0 {
		return errors.New("error internalId is 0 for LookupByInternalId")
	}
	return w.Tx.Where("id = ?", internalId).First(resource).Error
}

// LookupBy will lookup the first resource using a where clause with parameters (it only returns the first one)
func (w *GormReadWriter) LookupBy(ctx context.Context, resource interface{}, where string, args ...interface{}) error {
	if w.Tx == nil {
		return errors.New("error db nil for SearchBy")
	}
	if reflect.ValueOf(resource).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for LookupBy")
	}
	return w.Tx.Where(where, args...).First(resource).Error
}

// SearchBy will search for all the resources it can find using a where clause with parameters
func (w *GormReadWriter) SearchBy(ctx context.Context, resources interface{}, where string, args ...interface{}) error {
	if w.Tx == nil {
		return errors.New("error db nil for SearchBy")
	}
	if reflect.ValueOf(resources).Kind() != reflect.Ptr {
		return errors.New("error interface parameter must to be a pointer for SearchBy")
	}
	return w.Tx.Where(where, args...).Find(resources).Error
}
