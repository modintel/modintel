package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"modintel/services/auth-service/auth"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

func TestListSessionsUnauthorizedWhenClaimsMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)

	h.listSessions(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestListSessionsReturnsActiveSessions(t *testing.T) {
	mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock)).Run("ok", func(mt *mtest.T) {
		gin.SetMode(gin.TestMode)
		h := &Handler{tokens: mt.Coll}
		ns := mt.Coll.Database().Name() + "." + mt.Coll.Name()
		now := time.Now().UTC()
		oid := primitive.NewObjectID()

		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, ns, mtest.FirstBatch, bson.D{
				{Key: "_id", Value: oid},
				{Key: "user_id", Value: "user-1"},
				{Key: "token_hash", Value: "hash"},
				{Key: "jti", Value: "jti-1"},
				{Key: "user_agent", Value: "Mozilla/5.0"},
				{Key: "client_ip", Value: "127.0.0.1"},
				{Key: "created_at", Value: now},
				{Key: "last_used_at", Value: time.Time{}},
				{Key: "expires_at", Value: now.Add(30 * time.Minute)},
				{Key: "revoked", Value: false},
			}),
			mtest.CreateCursorResponse(0, ns, mtest.NextBatch),
		)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
		c.Set("access_claims", &auth.AccessClaims{UserID: "user-1"})

		h.listSessions(c)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var payload struct {
			Data struct {
				Sessions []map[string]any `json:"sessions"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(payload.Data.Sessions) != 1 {
			t.Fatalf("expected 1 session, got %d", len(payload.Data.Sessions))
		}
		if got := payload.Data.Sessions[0]["last_used_at"]; got != nil {
			t.Fatalf("expected null last_used_at for zero time, got %#v", got)
		}
	})
}

func TestRevokeSessionNotFound(t *testing.T) {
	mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock)).Run("not_found", func(mt *mtest.T) {
		gin.SetMode(gin.TestMode)
		h := &Handler{tokens: mt.Coll}
		oid := primitive.NewObjectID()

		mt.AddMockResponses(
			mtest.CreateSuccessResponse(
				bson.E{Key: "n", Value: int32(0)},
				bson.E{Key: "nModified", Value: int32(0)},
			),
		)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions/revoke", strings.NewReader(`{"session_id":"`+oid.Hex()+`"}`))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set("access_claims", &auth.AccessClaims{UserID: "user-1"})

		h.revokeSession(c)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})
}

func TestRevokeAllSessionsSuccess(t *testing.T) {
	mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock)).Run("ok", func(mt *mtest.T) {
		gin.SetMode(gin.TestMode)
		h := &Handler{tokens: mt.Coll}

		mt.AddMockResponses(
			mtest.CreateSuccessResponse(
				bson.E{Key: "n", Value: int32(2)},
				bson.E{Key: "nModified", Value: int32(2)},
			),
		)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions/revoke-all", strings.NewReader(`{}`))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set("access_claims", &auth.AccessClaims{UserID: "user-1"})

		h.revokeAllSessions(c)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}
