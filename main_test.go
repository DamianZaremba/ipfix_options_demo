package main

import (
	"github.com/hashicorp/golang-lru"
	"net"
	"testing"
)

var TEMPLATE_BYTES = []byte{0, 10, 0, 72, 90, 62, 128, 116, 0, 1, 119, 149, 0, 8, 0, 0, 0,
	3, 0, 56, 2, 0, 0, 11, 0, 1, 0, 144, 0, 4, 0, 41, 0, 8, 0, 42, 0, 8, 0, 160, 0, 8, 0, 130,
	0, 4, 0, 131, 0, 16, 0, 34, 0, 4, 0, 36, 0, 2, 0, 37, 0, 2, 0, 214, 0, 1, 0, 215, 0, 1, 0, 0}

var DATA_BYTES = []byte{0, 10, 0, 80, 90, 62, 128, 116, 0, 1, 119, 149, 0, 8, 0, 0, 2, 0,
	0, 64, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 250, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0,
	72, 192, 168, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 60, 0,
	15, 10, 17, 0, 0}

func parseTestOptions(t *testing.T) Options {
	// Create an in-memory cache to store the options template
	templateCache, err := lru.New(10240)
	if err != nil {
		t.Fatalf("Failed to setup options template cache: %v", err)
	}

	if _, ok := parsePayload(TEMPLATE_BYTES, templateCache); !ok {
		t.Errorf("Failed to parse valid template payload")
	}
	result, ok := parsePayload(DATA_BYTES, templateCache)
	if !ok {
		t.Errorf("Failed to parse valid data payload")
	}
	if len(result) == 0 {
		t.Errorf("Failed to load valid options")
	}
	return result
}

func TestInvalidPayload(t *testing.T) {
	// Create an in-memory cache to store the options template
	templateCache, err := lru.New(10240)
	if err != nil {
		t.Fatalf("Failed to setup options template cache: %v", err)
	}

	if _, ok := parsePayload([]byte{}, templateCache); ok {
		t.Errorf("Parsed invalid payload")
	}
}

func TestSingleOptionsTemplate(t *testing.T) {
	// Create an in-memory cache to store the options template
	templateCache, err := lru.New(10240)
	if err != nil {
		t.Fatalf("Failed to setup options template cache: %v", err)
	}

	result, ok := parsePayload(TEMPLATE_BYTES, templateCache)
	if !ok {
		t.Errorf("Failed to parse valid payload")
	}
	if len(result) > 0 {
		t.Errorf("Generated invalid payload")
	}
}

func TestSingleOptionsData(t *testing.T) {
	// Create an in-memory cache to store the options template
	templateCache, err := lru.New(10240)
	if err != nil {
		t.Fatalf("Failed to setup options template cache: %v", err)
	}

	result, ok := parsePayload(DATA_BYTES, templateCache)
	if !ok {
		t.Errorf("Failed to parse valid data payload")
	}
	if len(result) > 0 {
		t.Errorf("Generated invalid payload")
	}
}

func TestCompleteOptions(t *testing.T) {
	// Create an in-memory cache to store the options template
	templateCache, err := lru.New(10240)
	if err != nil {
		t.Fatalf("Failed to setup options template cache: %v", err)
	}

	if _, ok := parsePayload(TEMPLATE_BYTES, templateCache); !ok {
		t.Errorf("Failed to parse valid template payload")
	}
	result, ok := parsePayload(DATA_BYTES, templateCache)
	if !ok {
		t.Errorf("Failed to parse valid data payload")
	}
	if len(result) == 0 {
		t.Errorf("Failed to load valid options")
	}
}

func TestIpDecoding(t *testing.T) {
	parseTestOptions(t)
}

func TestIntervalDecoding(t *testing.T) {
	result := parseTestOptions(t)
	if val, ok := result["samplingInterval"]; !ok {
		t.Errorf("Failed to load valid samplingInterval field")
	} else if val.(uint32) != 10 {
		t.Errorf("Failed to load correct samplingInterval value")
	}
}

func TestExportDecoding(t *testing.T) {
	result := parseTestOptions(t)
	if val, ok := result["exporterIPv4Address"]; !ok {
		t.Errorf("Failed to load valid exporterIPv4Address field")
	} else if val.(net.IP).String() != "192.168.0.1" {
		t.Errorf("Failed to load correct exporterIPv4Address value")
	}

	if val, ok := result["exporterIPv6Address"]; !ok {
		t.Errorf("Failed to load valid exporterIPv6Address field")
	} else if val.(net.IP).String() != "::" {
		t.Errorf("Failed to load correct exporterIPv6Address value")
	}

	if val, ok := result["exportTransportProtocol"]; !ok {
		t.Errorf("Failed to load valid exportTransportProtocol field")
	} else if val.(uint8) != 17 {
		t.Errorf("Failed to load correct exportTransportProtocol value")
	}

	if val, ok := result["exportProtocolVersion"]; !ok {
		t.Errorf("Failed to load valid exportProtocolVersion field")
	} else if val.(uint8) != 10 {
		t.Errorf("Failed to load correct exportProtocolVersion value")
	}

	if val, ok := result["exportingProcessId"]; !ok {
		t.Errorf("Failed to load valid exportingProcessId field")
	} else if val.(int64) != 72 {
		t.Errorf("Failed to load correct exportingProcessId value")
	}
}

func TestFlowMetaDecoding(t *testing.T) {
	result := parseTestOptions(t)
	if val, ok := result["flowActiveTimeout"]; !ok {
		t.Errorf("Failed to load valid flowActiveTimeout field")
	} else if val.(uint16) != 60 {
		t.Errorf("Failed to load correct flowActiveTimeout value")
	}

	if val, ok := result["flowIdleTimeout"]; !ok {
		t.Errorf("Failed to load valid flowIdleTimeout field")
	} else if val.(uint16) != 15 {
		t.Errorf("Failed to load correct flowIdleTimeout value")
	}
}

func TestFlowCountDecoding(t *testing.T) {
	result := parseTestOptions(t)
	if val, ok := result["exportedFlowRecordTotalCount"]; !ok {
		t.Errorf("Failed to load valid exportedFlowRecordTotalCount field")
	} else if val.(uint64) != 10 {
		t.Errorf("Failed to load correct exportedFlowRecordTotalCount value")
	}

	if val, ok := result["exportedMessageTotalCount"]; !ok {
		t.Errorf("Failed to load valid exportedMessageTotalCount field")
	} else if val.(uint64) != 250 {
		t.Errorf("Failed to load correct exportedMessageTotalCount value")
	}
}
