package api

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type CursorPaginationParams struct {
	Cursor string
	Limit  int
}

type OffsetPaginationParams struct {
	Page  int
	Limit int
}

type CursorResponse struct {
	Data       interface{} `json:"data"`
	NextCursor *string     `json:"next_cursor,omitempty"`
	Limit      int         `json:"limit"`
}

type OffsetResponse struct {
	Data       interface{} `json:"data"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalCount int64       `json:"total_count"`
	TotalPages int         `json:"total_pages"`
}

func parseCursorParams(c *gin.Context) (*CursorPaginationParams, error) {
	cursorStr := strings.TrimSpace(c.Query("cursor"))
	limitStr := strings.TrimSpace(c.Query("limit"))

	limit := 50
	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit < 1 || parsedLimit > 500 {
			return nil, fmt.Errorf("limit must be between 1 and 500")
		}
		limit = parsedLimit
	}

	return &CursorPaginationParams{
		Cursor: cursorStr,
		Limit:  limit,
	}, nil
}

func parseOffsetParams(c *gin.Context) (*OffsetPaginationParams, error) {
	pageStr := strings.TrimSpace(c.Query("page"))
	limitStr := strings.TrimSpace(c.Query("limit"))

	page := 1
	if pageStr != "" {
		parsedPage, err := strconv.Atoi(pageStr)
		if err != nil || parsedPage < 1 {
			return nil, fmt.Errorf("invalid pagination parameters")
		}
		page = parsedPage
	}

	limit := 50
	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit < 1 || parsedLimit > 500 {
			return nil, fmt.Errorf("limit must be between 1 and 500")
		}
		limit = parsedLimit
	}

	return &OffsetPaginationParams{
		Page:  page,
		Limit: limit,
	}, nil
}

func buildCursorFilter(cursor string) (bson.M, error) {
	if cursor == "" {
		return bson.M{}, nil
	}

	objectID, err := primitive.ObjectIDFromHex(cursor)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}

	return bson.M{"_id": bson.M{"$lt": objectID}}, nil
}
