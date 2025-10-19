package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/tidwall/gjson"
)

const (
	resourceType = "toy_resource"
)

// getLineNumber extracts the line number from the JSON content for a given JSON path
func getLineNumber(jsonContent string, jsonPaths string) (int, error) {
	// get the result from the json content for its Index field
	result := gjson.Get(jsonContent, jsonPaths)
	if !result.Exists() {
		return 0, fmt.Errorf("path '%s' not found in JSON", jsonPaths)
	}

	// get the line number from the index
	offset := result.Index
	lineNumber := 1 + strings.Count(jsonContent[:offset], "\n")

	return lineNumber, nil
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

		lineNum, err := getLineNumber(jsonContent, path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

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

	// extract risk paths
	riskPathsInterface := resultSet[0].Bindings["risk_path"]

	// convert to slice for processing
	var riskPaths []interface{}
	switch v := riskPathsInterface.(type) {
	case []interface{}:
		riskPaths = v
	default:
		riskPaths = []interface{}{v}
	}

	// get line numbers
	riskLines := getRiskLines(resourceDeclarationFileAbsolutePath, riskPaths)

	fmt.Println("Risk Paths: ", resultSet[0].Bindings["risk_path"])
	fmt.Println("Risk Lines: ", riskLines)
}
