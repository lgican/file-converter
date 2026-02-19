// Package bank implements the CSV to fixed-width bank file format converter.
// It is automatically registered with the formats registry on import.
package bank

import (
	"strings"

	"github.com/lgican/File-Converter/formats"
	parser "github.com/lgican/File-Converter/parsers/bank"
)

func init() {
	formats.Register(&converter{})
}

type converter struct{}

func (c *converter) Name() string {
	return "Bank File (CSV)"
}

func (c *converter) Extensions() []string {
	return []string{".csv"}
}

func (c *converter) Match(data []byte) bool {
	// Check if it looks like a CSV file (has comma-separated values)
	s := string(data)
	if len(s) < 10 {
		return false
	}

	// Look for CSV patterns in the first few lines
	lines := strings.Split(s, "\n")
	if len(lines) < 2 {
		return false
	}

	// Check first line has commas and second line also has commas
	firstLine := lines[0]
	if strings.Count(firstLine, ",") < 1 {
		return false
	}

	// Basic CSV detection - at least 2 fields separated by commas
	return strings.Contains(firstLine, ",")
}

func (c *converter) Convert(data []byte) ([]formats.ConvertedFile, error) {
	// For CSV files, we'll return the original CSV and optionally formatted versions
	// Using the default template (ACH_Payment) as an example
	// In a real implementation, template selection would come from the web UI

	var files []formats.ConvertedFile

	// Always include the original CSV
	files = append(files, formats.ConvertedFile{
		Name:     "original.csv",
		Data:     data,
		Category: "body",
	})

	// Try to format with available templates
	templates := []string{"BeanStream_Detail", "ACH_Payment", "Wire_Transfer", "Direct_Deposit"}

	for _, templateKey := range templates {
		bankFile, err := parser.Decode(data, templateKey)
		if err != nil {
			continue // Skip templates that don't work with this data
		}

		formatted := bankFile.Format()
		files = append(files, formats.ConvertedFile{
			Name:     templateKey + ".txt",
			Data:     formatted,
			Category: "attachment",
		})
	}

	return files, nil
}
