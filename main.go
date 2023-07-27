package main

import (
	"bytes"
	"fmt"
	"github.com/hillu/go-yara/v4"
	"log"
	"os"
)

func printMatches(item string, m []yara.MatchRule, err error) {
	if err != nil {
		log.Printf("%s: error: %s", item, err)
		return
	}
	if len(m) == 0 {
		log.Printf("%s: no matches", item)
		return
	}
	fmt.Print("Matched rules:\t", len(m), "\n")
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%s: [", item)
	for i, match := range m {
		if i > 0 {
			fmt.Fprint(buf, ", ")
		}
		fmt.Fprintf(buf, "%s:%s", match.Namespace, match.Rule)
	}
	fmt.Fprint(buf, "]")
	log.Print(buf.String())
}

func main() {

	compiler, err := yara.NewCompiler()
	if err != nil {
		fmt.Println("Error loading compiler: ", err)
	}
	defer compiler.Destroy()

	// rule file to load
	malware_file, err := os.Open("all_combined_malware_rules.yar")
	if err != nil {
		fmt.Println("Error opening malware rule file: ", err)
	}

	err = compiler.AddFile(malware_file, "")
	defer malware_file.Close()
	if err != nil {
		fmt.Println("Error adding malware rule file : ", err)
	}

	rules, err := compiler.GetRules()
	if err != nil {
		fmt.Println("Error getting rules: ", err)
		log.Fatal(err)
	}

	scanner, err := yara.NewScanner(rules)
	if err != nil {
		fmt.Println("Error creating scanner: ", err)
	}
	defer scanner.Destroy()

	// file to scan
	filepath := "eicar_com.zip"

	// scan file
	log.Printf(" Scanning file %s... ", filepath)

	var matchrule yara.MatchRules
	// err = scanner.ScanFile(filepath)
	err = scanner.SetCallback(&matchrule).ScanFile(filepath)
	if err != nil {
		fmt.Println("Error scanning file: ", err)
	}
	printMatches(filepath, matchrule, err)
}
