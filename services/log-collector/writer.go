package main

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func bulkWriter(ctx context.Context, collection *mongo.Collection, ch <-chan writeModel) {
	const (
		maxBatchSize = 50
		flushEvery   = 2 * time.Second
	)

	batch := make([]writeModel, 0, maxBatchSize)
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		models := make([]mongo.WriteModel, 0, len(batch))
		for _, wm := range batch {
			models = append(models, mongo.NewUpdateOneModel().
				SetFilter(bson.M{"alert_key": wm.alertKey}).
				SetUpdate(bson.M{"$set": wm.docMap}).
				SetUpsert(true),
			)
		}
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		res, err := collection.BulkWrite(writeCtx, models, options.BulkWrite().SetOrdered(false))
		cancel()
		if err != nil {
			log.Printf("BulkWrite error: %v", err)
		} else {
			log.Printf("BulkWrite: upserted=%d modified=%d", res.UpsertedCount, res.ModifiedCount)
		}
		batch = batch[:0]
	}

	for {
		select {
		case wm, ok := <-ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, wm)
			if len(batch) >= maxBatchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-ctx.Done():
			flush()
			return
		}
	}
}
