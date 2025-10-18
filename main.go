package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
)

const (
	resourceType = "toy_resource"
)

// findLineNumber finds the line number for a given dot-notated path in JSON
func findLineNumber(jsonContent string, path string) int {
	lines := strings.Split(jsonContent, "\n")
	parts := strings.Split(path, ".")
	currentLine := 0
	lastKeyLine := 0     // the last line where we matched a non-array key
	partIndex := 0

	lineNum := 0
	N := len(lines)

	for lineNum < N {
		line := lines[lineNum]
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and schema lines
		if trimmed == "" || strings.HasPrefix(trimmed, "\"$schema\"") ||
			strings.HasPrefix(trimmed, "\"contentVersion\"") {
			lineNum++
			continue
		}

		if partIndex >= len(parts) {
			return currentLine
		}

		currentPart := parts[partIndex]

		// If this part is an array index: find the correct element start
		if isArrayIndex(currentPart) {
			targetIdx, _ := strconv.Atoi(currentPart)

			// Find the first "{" after lastKeyLine - that will be the first array element start.
			foundLine := -1
			baseIndent := -1
			for l := lastKeyLine; l < N; l++ {
				if strings.TrimSpace(lines[l]) == "{" {
					// this is candidate first element; record its indent
					baseIndent = len(lines[l]) - len(strings.TrimLeft(lines[l], " "))
					// count only '{' that have the same indentation level (top-level elements)
					elementCount := -1
					for m := l; m < N; m++ {
						if strings.TrimSpace(lines[m]) == "{" {
							indent := len(lines[m]) - len(strings.TrimLeft(lines[m], " "))
							if indent == baseIndent {
								elementCount++
								if elementCount == targetIdx {
									foundLine = m
									break
								}
							}
						}
					}
					break
				}
			}

			if foundLine == -1 {
				// couldn't find the requested array element; return 0 (or currentLine)
				return currentLine
			}

			// Set current line to the element's opening '{' and advance parser state
			currentLine = foundLine + 1
			partIndex++
			// continue scanning from the found element's line (so subsequent key matches happen inside it)
			lineNum = foundLine + 1
			continue
		}

		// Otherwise, look for a key on this line
		keyPattern := fmt.Sprintf("\"%s\"\\s*:", regexp.QuoteMeta(currentPart))
		matched, _ := regexp.MatchString(keyPattern, line)
		if matched {
			currentLine = lineNum + 1
			lastKeyLine = lineNum
			partIndex++
			if partIndex >= len(parts) {
				return currentLine
			}
		}

		lineNum++
	}

	return currentLine
}

// isArrayIndex checks if a string is a number (array index)
func isArrayIndex(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// getRiskLines extracts line numbers for all risk paths
func getRiskLines(jsonFilePath string, riskPaths []interface{}) []int {
	content, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return []int{}
	}
	
	jsonContent := string(content)
	lines := []int{}
	
	for _, pathInterface := range riskPaths {
		path, ok := pathInterface.(string)
		if !ok {
			continue
		}
		
		lineNum := findLineNumber(jsonContent, path)
		lines = append(lines, lineNum)
	}
	
	return lines
}


func main() {
	ctx := context.Background()
	// load risk policies
	var err error
	var policies *loader.Result

	policyAbsolutePath, _ := filepath.Abs(fmt.Sprintf("policies/%v/policy.rego", resourceType))
	if policies, err = loader.NewFileLoader().Filtered([]string{policyAbsolutePath}, func(_ string, info os.FileInfo, _ int) bool {
		return !info.IsDir() && !strings.HasSuffix(info.Name(), bundle.RegoExt)
	}); err != nil {
		panic(err)
	}

	compiler :=
		ast.NewCompiler().
			WithEnablePrintStatements(true).
			WithStrict(true).
			WithUnsafeBuiltins(map[string]struct{}{
				ast.HTTPSend.Name:   {},
				ast.OPARuntime.Name: {},
			})

	// compile risk policies
	compiler.Compile(policies.ParsedModules())
	if compiler.Failed() {
		panic(compiler.Errors)
	}

	// read resource declaration file
	resourceDeclarationFileAbsolutePath, _ := filepath.Abs(fmt.Sprintf("policies/%v/positive.json", resourceType))
	resourceFileContent, err := os.ReadFile(resourceDeclarationFileAbsolutePath)
	if err != nil {
		panic(err)
	}

	var resourceFileInput map[string]any
	err = json.Unmarshal(resourceFileContent, &resourceFileInput)
	if err != nil {
		panic(err)
	}

	// query the resource declaration file for risks
	var preparedEvalQuery rego.PreparedEvalQuery
	if preparedEvalQuery, err =
		rego.New(
			rego.Compiler(compiler),
			rego.PrintHook(topdown.NewPrintHook(os.Stdout)),
			rego.Query("risk_path = data.example.analyze"),
			rego.Input(resourceFileInput),
		).PrepareForEval(ctx); err != nil {
		panic(err)
	}

	// print the resultant risks
	var resultSet rego.ResultSet
	if resultSet, err = preparedEvalQuery.Eval(ctx); err != nil {
		panic(err)
	}
	
	// Extract risk paths
	riskPathsInterface := resultSet[0].Bindings["risk_path"]
	
	// Convert to slice for processing
	var riskPaths []interface{}
	switch v := riskPathsInterface.(type) {
	case []interface{}:
		riskPaths = v
	default:
		riskPaths = []interface{}{v}
	}
	
	// Get line numbers
	riskLines := getRiskLines(resourceDeclarationFileAbsolutePath, riskPaths)

	fmt.Println("Risk Paths: ", resultSet[0].Bindings["risk_path"])
	fmt.Println("Risk Lines: ", riskLines)
}
