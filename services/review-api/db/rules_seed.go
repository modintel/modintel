package db

import (
	"bufio"
	"context"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// SeedWAFRules seeds both custom and CRS rules into MongoDB
func SeedWAFRules() {
	log.Println("🔥 SeedWAFRules STARTED")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Seed custom rules from custom_rules.conf
	customCount := seedCustomRules(ctx)
	log.Printf("✓ Seeded %d custom rules", customCount)

	// Seed CRS rules from mounted volume (if available)
	crsCount := seedCRSRules(ctx)
	log.Printf("✓ Seeded %d CRS rules", crsCount)

	log.Println("✓ WAF rules seeding complete")
}

// seedCustomRules parses custom_rules.conf and seeds into MongoDB
func seedCustomRules(ctx context.Context) int {
	customRulesPath := os.Getenv("CUSTOM_RULES_PATH")
	if customRulesPath == "" {
		customRulesPath = "/waf-overrides/../custom_rules.conf" // Default path
	}

	// Try alternative paths if default doesn't exist
	if _, err := os.Stat(customRulesPath); os.IsNotExist(err) {
		customRulesPath = "/project/proxy-waf/custom_rules.conf"
	}

	file, err := os.Open(customRulesPath)
	if err != nil {
		log.Printf("⚠ Custom rules file not found at %s: %v", customRulesPath, err)
		return 0
	}
	defer file.Close()

	coll := GetCollection("modintel", "waf_rules")
	scanner := bufio.NewScanner(file)
	count := 0

	// Regex to parse SecRule directives
	ruleRegex := regexp.MustCompile(`id:(\d+)`)
	msgRegex := regexp.MustCompile(`msg:'([^']*)'`)
	phaseRegex := regexp.MustCompile(`phase:(\d+)`)
	tagRegex := regexp.MustCompile(`tag:'([^']*)'`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Only process SecRule lines
		if !strings.HasPrefix(line, "SecRule") {
			continue
		}

		// Extract rule ID
		idMatch := ruleRegex.FindStringSubmatch(line)
		if len(idMatch) < 2 {
			continue
		}
		ruleID := idMatch[1]

		// Extract message (description)
		description := "Custom WAF Rule"
		if msgMatch := msgRegex.FindStringSubmatch(line); len(msgMatch) >= 2 {
			description = msgMatch[1]
		}

		// Extract phase
		phase := 2 // Default phase
		if phaseMatch := phaseRegex.FindStringSubmatch(line); len(phaseMatch) >= 2 {
			if p, err := strconv.Atoi(phaseMatch[1]); err == nil {
				phase = p
			}
		}

		// Extract category from tags
		category := "Generic"
		tags := tagRegex.FindAllStringSubmatch(line, -1)
		for _, tagMatch := range tags {
			if len(tagMatch) >= 2 {
				tag := tagMatch[1]
				// Skip 'custom' tag, use attack type tags
				if tag != "custom" && tag != "" {
					category = strings.ToUpper(tag)
					break
				}
			}
		}

		// Determine severity based on action
		severity := "MEDIUM"
		if strings.Contains(line, "deny") {
			severity = "HIGH"
		} else if strings.Contains(line, "pass") {
			severity = "MEDIUM"
		}

		now := time.Now()

		// Upsert rule (preserve existing enabled state)
		filter := bson.M{"id": ruleID}
		update := bson.M{
			"$setOnInsert": bson.M{
				"id":          ruleID,
				"type":        "custom",
				"source":      "modintel-custom",
				"enabled":     true,
				"archived":    false,
				"created_at":  now,
			},
			"$set": bson.M{
				"description": description,
				"category":    category,
				"severity":    severity,
				"phase":       phase,
				"updated_at":  now,
			},
		}

		opts := options.Update().SetUpsert(true)
		result, err := coll.UpdateOne(ctx, filter, update, opts)
		if err != nil {
			log.Printf("⚠ Error seeding custom rule %s: %v", ruleID, err)
			continue
		}

		if result.UpsertedCount > 0 {
			log.Printf("  → Inserted custom rule: %s (%s)", ruleID, category)
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("⚠ Error reading custom rules file: %v", err)
	}

	return count
}

// seedCRSRules parses CRS rule files and seeds into MongoDB
func seedCRSRules(ctx context.Context) int {
	crsRulesPath := os.Getenv("CRS_RULES_PATH")
	if crsRulesPath == "" {
		crsRulesPath = "/opt/coraza/owasp-crs/rules"
	}

	// Check if CRS rules directory exists
	if _, err := os.Stat(crsRulesPath); os.IsNotExist(err) {
		log.Printf("⚠ CRS rules directory not found at %s (will be mounted in production)", crsRulesPath)
		return 0
	}

	coll := GetCollection("modintel", "waf_rules")
	count := 0

	// Read all .conf files in the CRS rules directory
	entries, err := os.ReadDir(crsRulesPath)
	if err != nil {
		log.Printf("⚠ Cannot read CRS rules directory: %v", err)
		return 0
	}

	// Regex patterns for parsing CRS rules
	ruleRegex := regexp.MustCompile(`SecRule\s+`)
	chainRegex := regexp.MustCompile(`chain`)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		filePath := crsRulesPath + "/" + entry.Name()
		file, err := os.Open(filePath)
		if err != nil {
			log.Printf("⚠ Cannot open CRS file %s: %v", entry.Name(), err)
			continue
		}

		scanner := bufio.NewScanner(file)
		var currentRule strings.Builder
		isChainChild := false

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// Skip comments and empty lines
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Check if this is a chain child (continuation of previous rule)
			if !ruleRegex.MatchString(line) && currentRule.Len() > 0 {
				currentRule.WriteString(" " + line)
				continue
			}

			// Process accumulated rule
			if currentRule.Len() > 0 {
				processedCount := processCRSRule(ctx, coll, currentRule.String(), isChainChild)
				count += processedCount
				currentRule.Reset()
			}

			// Start new rule
			if ruleRegex.MatchString(line) {
				currentRule.WriteString(line)
				isChainChild = chainRegex.MatchString(line)
			}
		}

		// Process last rule in file
		if currentRule.Len() > 0 {
			processedCount := processCRSRule(ctx, coll, currentRule.String(), isChainChild)
			count += processedCount
		}

		file.Close()
	}

	return count
}

// processCRSRule parses and inserts a single CRS rule
func processCRSRule(ctx context.Context, coll *mongo.Collection, ruleText string, isChainChild bool) int {
	// Skip chain children (they don't have standalone IDs)
	if isChainChild {
		return 0
	}

	// Extract rule ID
	idRegex := regexp.MustCompile(`id:(\d+)`)
	idMatch := idRegex.FindStringSubmatch(ruleText)
	if len(idMatch) < 2 {
		return 0
	}
	ruleID := idMatch[1]

	// Determine rule type based on ID prefix
	ruleType := "crs"
	if strings.HasPrefix(ruleID, "949") || strings.HasPrefix(ruleID, "959") {
		ruleType = "crs-blocking"
	}
	// 901xxx are initialization rules (not detection, not blocking)
	if strings.HasPrefix(ruleID, "901") {
		ruleType = "crs-init"
	}

	// Extract description
	msgRegex := regexp.MustCompile(`msg:'([^']*)'`)
	description := "CRS Detection Rule"
	if ruleType == "crs-blocking" {
		description = "CRS Blocking Evaluation Rule"
	} else if ruleType == "crs-init" {
		description = "CRS Initialization Rule"
	}
	if msgMatch := msgRegex.FindStringSubmatch(ruleText); len(msgMatch) >= 2 {
		description = msgMatch[1]
	}

	// Extract severity
	severityRegex := regexp.MustCompile(`severity:'([^']*)'`)
	severity := "MEDIUM"
	if sevMatch := severityRegex.FindStringSubmatch(ruleText); len(sevMatch) >= 2 {
		severity = strings.ToUpper(sevMatch[1])
	}

	// Extract phase
	phaseRegex := regexp.MustCompile(`phase:(\d+)`)
	phase := 2
	if phaseMatch := phaseRegex.FindStringSubmatch(ruleText); len(phaseMatch) >= 2 {
		if p, err := strconv.Atoi(phaseMatch[1]); err == nil {
			phase = p
		}
	}

	// Extract category from tags
	category := "Generic"
	if ruleType == "crs-blocking" {
		category = "Blocking Evaluation"
	} else if ruleType == "crs-init" {
		category = "Initialization"
	} else {
		tagRegex := regexp.MustCompile(`tag:'([^']*)'`)
		tags := tagRegex.FindAllStringSubmatch(ruleText, -1)
		for _, tagMatch := range tags {
			if len(tagMatch) >= 2 {
				tag := tagMatch[1]
				if strings.HasPrefix(tag, "attack-") {
					category = mapCRSTagToCategory(tag)
					break
				}
			}
		}
	}

	// Extract paranoia level
	paranoiaLevel := 1
	plRegex := regexp.MustCompile(`tag:'paranoia-level/(\d+)'`)
	if plMatch := plRegex.FindStringSubmatch(ruleText); len(plMatch) >= 2 {
		if pl, err := strconv.Atoi(plMatch[1]); err == nil {
			paranoiaLevel = pl
		}
	}

	now := time.Now()

	// Upsert rule (preserve existing enabled state)
	filter := bson.M{"id": ruleID}
	update := bson.M{
		"$setOnInsert": bson.M{
			"id":          ruleID,
			"source":      "owasp-crs",
			"enabled":     true,
			"archived":    false,
			"created_at":  now,
		},
		"$set": bson.M{
			"type":           ruleType,
			"description":    description,
			"category":       category,
			"severity":       severity,
			"phase":          phase,
			"paranoia_level": paranoiaLevel,
			"updated_at":     now,
		},
	}

	opts := options.Update().SetUpsert(true)
	result, err := coll.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		log.Printf("⚠ Error seeding CRS rule %s: %v", ruleID, err)
		return 0
	}

	if result.UpsertedCount > 0 {
		return 1
	}

	return 0
}

// mapCRSTagToCategory maps CRS attack tags to categories
func mapCRSTagToCategory(tag string) string {
	tagMap := map[string]string{
		"attack-sqli":           "SQLi",
		"attack-xss":            "XSS",
		"attack-lfi":            "LFI",
		"attack-rfi":            "RFI",
		"attack-rce":            "RCE",
		"attack-execution":      "RCE",
		"attack-injection-php":  "PHP",
		"attack-protocol":       "Protocol",
		"attack-generic":        "Generic",
		"attack-session":        "Session Fixation",
		"attack-java":           "Java",
		"attack-scanner":        "Scanner Detection",
		"attack-multipart":      "Multipart",
		"leakage-":              "Data Leakage",
		"web-shells":            "Web Shells",
		"attack-cmdexec":        "CMDi",
		"attack-injection":      "Injection",
		"attack-disclosure":     "Information Disclosure",
		"attack-fixation":       "Session Fixation",
		"attack-automation":     "Automation",
	}

	for prefix, category := range tagMap {
		if strings.HasPrefix(tag, prefix) {
			return category
		}
	}

	return "Generic"
}
