package utils

import (
	"fmt"
	"strconv"
	"strings"
)

// expandNodeName expands a hostname with range brackets like nodename[1-3,5,7-9]
func ExpandNodeName(input string) ([]string, error) {
	if !strings.Contains(input, "[") || !strings.Contains(input, "]") {
		return []string{input}, nil
	}

	// Split prefix and ranges
	prefix := input[:strings.Index(input, "[")]
	rangePart := input[strings.Index(input, "[")+1 : strings.Index(input, "]")]

	// Split range part by commas
	parts := strings.Split(rangePart, ",")
	var result []string

	for _, part := range parts {
		if strings.Contains(part, "-") {
			// Handle range like 1-3
			rangeBounds := strings.Split(part, "-")
			if len(rangeBounds) != 2 {
				return nil, fmt.Errorf("invalid range format in '%s'", part)
			}
			start, err := strconv.Atoi(rangeBounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start value in range '%s'", part)
			}
			end, err := strconv.Atoi(rangeBounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end value in range '%s'", part)
			}
			if start > end {
				return nil, fmt.Errorf("start value cannot be greater than end value in range '%s'", part)
			}
			for i := start; i <= end; i++ {
				result = append(result, fmt.Sprintf("%s%d", prefix, i))
			}
		} else {
			// Handle single value like 5
			value, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid value '%s'", part)
			}
			result = append(result, fmt.Sprintf("%s%d", prefix, value))
		}
	}

	return result, nil
}
